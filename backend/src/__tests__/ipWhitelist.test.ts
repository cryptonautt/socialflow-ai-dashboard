import { Request, Response, NextFunction } from 'express';
import { ipWhitelistMiddleware } from '../middleware/ipWhitelist';
import * as runtime from '../config/runtime';
import { dynamicConfigService } from '../services/DynamicConfigService';
import requestIp from 'request-ip';

jest.mock('../config/runtime');
jest.mock('request-ip');
jest.mock('../services/DynamicConfigService', () => ({
  dynamicConfigService: {
    get: jest.fn(),
  },
  ConfigKey: {
    ADMIN_IP_WHITELIST: 'ADMIN_IP_WHITELIST',
  },
}));
jest.mock('../lib/logger', () => ({
  createLogger: () => ({
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
  }),
}));

describe('ipWhitelistMiddleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction = jest.fn();

  beforeEach(() => {
    mockRequest = {
      path: '/api/v1/health',
      method: 'GET',
      headers: {},
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    (nextFunction as jest.Mock).mockClear();
    (dynamicConfigService.get as jest.Mock).mockReturnValue('');
    jest.clearAllMocks();
  });

  it('should allow access if whitelist is empty', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue([]);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('127.0.0.1');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access if client IP matches an exact entry', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['127.0.0.1', '192.168.1.1']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('192.168.1.1');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access if client IP matches a CIDR range', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['192.168.1.0/24']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('192.168.1.50');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access for IPv6 addresses', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['2001:db8::/32']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('2001:db8:85a3::8a2e:370:7334');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should block access if client IP is not whitelisted', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['127.0.0.1', '10.0.0.0/8']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('192.168.1.1');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    
    expect(nextFunction).not.toHaveBeenCalled();
    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith({
      error: 'Access forbidden: Your IP address is not authorized to access this endpoint.'
    });
  });

  it('should block access and return 403 if client IP cannot be determined', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['127.0.0.1']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue(null);

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);

    expect(nextFunction).not.toHaveBeenCalled();
    expect(mockResponse.status).toHaveBeenCalledWith(403);
  });

  it('should skip invalid CIDR entries in the whitelist', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['invalid-ip', '127.0.0.1']);
    (requestIp.getClientIp as jest.Mock).mockReturnValue('127.0.0.1');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access if client IP matches a DB-configured entry', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue([]);
    (dynamicConfigService.get as jest.Mock).mockReturnValue('10.0.0.5');
    (requestIp.getClientIp as jest.Mock).mockReturnValue('10.0.0.5');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access if client IP matches a DB-configured CIDR range', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue([]);
    (dynamicConfigService.get as jest.Mock).mockReturnValue('172.16.0.0/12');
    (requestIp.getClientIp as jest.Mock).mockReturnValue('172.16.0.100');

    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should allow access if client IP matches either ENV or DB', () => {
    (runtime.getAdminIpWhitelist as jest.Mock).mockReturnValue(['127.0.0.1']);
    (dynamicConfigService.get as jest.Mock).mockReturnValue('192.168.1.1');
    
    // Test ENV match
    (requestIp.getClientIp as jest.Mock).mockReturnValue('127.0.0.1');
    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();

    // Test DB match
    (nextFunction as jest.Mock).mockClear();
    (requestIp.getClientIp as jest.Mock).mockReturnValue('192.168.1.1');
    ipWhitelistMiddleware(mockRequest as Request, mockResponse as Response, nextFunction);
    expect(nextFunction).toHaveBeenCalled();
  });
});
