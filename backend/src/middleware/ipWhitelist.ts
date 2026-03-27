import { Request, Response, NextFunction } from 'express';
import requestIp from 'request-ip';
import ipaddr from 'ipaddr.js';
import { getAdminIpWhitelist } from '../config/runtime';
import { createLogger } from '../lib/logger';
import { dynamicConfigService, ConfigKey } from '../services/DynamicConfigService';

const logger = createLogger('middleware:ipWhitelist');

/**
 * Middleware to restrict access to specific IP addresses and CIDR ranges.
 * Supports IPv4 and IPv6, and handles proxy headers safely if the app is 
 * configured to trust proxies.
 */
export const ipWhitelistMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const clientIp = requestIp.getClientIp(req);
  
  // Fetch from ENV
  const envWhitelist = getAdminIpWhitelist();
  
  // Fetch from DB
  const dbWhitelistRaw = dynamicConfigService.get<string>(ConfigKey.ADMIN_IP_WHITELIST, '');
  const dbWhitelist = dbWhitelistRaw
    .split(',')
    .map((val) => val.trim())
    .filter(Boolean);

  // Merge and de-duplicate
  const whitelist = Array.from(new Set([...envWhitelist, ...dbWhitelist]));

  // If no whitelist is configured, allow all by default
  if (whitelist.length === 0) {
    return next();
  }

  if (!clientIp) {
    logger.warn('Could not determine client IP for whitelisting', {
      path: req.path,
      method: req.method,
    });
    return res.status(403).json({ error: 'Access forbidden: Could not determine client IP' });
  }

  try {
    const addr = ipaddr.parse(clientIp);
    const isAllowed = whitelist.some((entry) => {
      try {
        if (entry.includes('/')) {
          // CIDR range
          const [range, bits] = entry.split('/');
          const network = ipaddr.parse(range);
          const bitCount = parseInt(bits, 10);
          
          // Ensure both are same version (v4 or v6)
          if (addr.kind() === network.kind()) {
            return (addr as any).match(network, bitCount);
          }
          return false;
        } else {
          // Exact IP
          const allowedAddr = ipaddr.parse(entry);
          return addr.toString() === allowedAddr.toString();
        }
      } catch (err) {
        logger.error('Invalid entry in IP whitelist', { entry, error: err instanceof Error ? err.message : String(err) });
        return false;
      }
    });

    if (isAllowed) {
      return next();
    }

    logger.warn('Blocked unauthorized IP attempt', {
      ip: clientIp,
      path: req.path,
      method: req.method,
    });
  } catch (err) {
    logger.error('Error parsing client IP or checking whitelist', {
      ip: clientIp,
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return res.status(403).json({ 
    error: 'Access forbidden: Your IP address is not authorized to access this endpoint.' 
  });
};
