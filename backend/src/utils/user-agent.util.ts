import * as UAParser from 'ua-parser-js';

export interface DeviceInfo {
  deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
  browser: string;
  browserVersion: string;
  os: string;
  osVersion: string;
  deviceName: string;
}

export const parseUserAgent = (userAgent: string): DeviceInfo => {
  const parser = new UAParser.UAParser(userAgent);
  const result = parser.getResult();

  let deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown' = 'unknown';
  
  if (result.device.type === 'mobile') {
    deviceType = 'mobile';
  } else if (result.device.type === 'tablet') {
    deviceType = 'tablet';
  } else if (result.device.type === undefined) {
    deviceType = 'desktop';
  }

  const browser = result.browser.name || 'Unknown';
  const browserVersion = result.browser.version || '';
  const os = result.os.name || 'Unknown';
  const osVersion = result.os.version || '';
  
  const deviceName = `${browser} on ${os}`;

  return {
    deviceType,
    browser,
    browserVersion,
    os,
    osVersion,
    deviceName
  };
};

export const generateDeviceId = (userAgent: string, ip: string): string => {
  const crypto = require('crypto');
  return crypto
    .createHash('sha256')
    .update(`${userAgent}-${ip}`)
    .digest('hex')
    .substring(0, 32);
};