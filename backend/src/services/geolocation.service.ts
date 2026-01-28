import geoip from 'geoip-lite';
import NodeCache from 'node-cache';

export interface GeoLocation {
  ip: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp?: string;
  isVPN?: boolean;
  isProxy?: boolean;
  isAnonymous?: boolean;
}

class GeolocationService {
  private cache: NodeCache;
  private mockLocations: Record<string, GeoLocation>;
  
  constructor() {
    // Cache geolocation results for 24 hours
    this.cache = new NodeCache({ 
      stdTTL: parseInt(process.env.GEO_CACHE_TTL || '86400') 
    });

    // TEMPORARY MOCK LOCATIONS FOR TESTING
    this.mockLocations = {
      '127.0.0.1': {
        ip: '127.0.0.1',
        country: 'DE',
        region: 'Berlin',
        city: 'Berlin',
        latitude: 52.52,
        longitude: 13.405,
        timezone: 'Europe/Berlin',
        isVPN: false,
        isProxy: false,
        isAnonymous: false
      },
      '127.0.0.2': {
        ip: '127.0.0.2',
        country: 'US',
        region: 'California',
        city: 'San Francisco',
        latitude: 37.7749,
        longitude: -122.4194,
        timezone: 'America/Los_Angeles',
        isVPN: false,
        isProxy: false,
        isAnonymous: false
      },
      '123.123.123.123': {
        ip: '123.123.123.123',
        country: 'DE',
        region: 'TestRegion',
        city: 'Munich',
        latitude: 48.1351,
        longitude: 11.5820,
        timezone: 'Europe/Berlin',
        isVPN: false,
        isProxy: false,
        isAnonymous: false
      }
    };
  }

  /**
   * Get geolocation data from IP address
   */
  async getLocationFromIP(ip: string, forceRefresh= false): Promise<GeoLocation | null> {
    try {
      if(!forceRefresh){
        const cached = this.cache.get<GeoLocation>(ip);
        if (cached) {
          return cached;
        }
      }
      // Check cache first
      const cached = this.cache.get<GeoLocation>(ip);
      if (cached) {
        return cached;
      }

      // TEMPORARY MOCK LOCATIONS FOR TESTING
      if (this.isLocalIP(ip) || process.env.NODE_ENV === 'development') {
        // Check for mock location
        if (this.mockLocations[ip]) {
          const mockLocation = { ...this.mockLocations[ip] };
          this.cache.set(ip, mockLocation);
          return mockLocation;
        }

        // Fallback for localhost
        const localLocation: GeoLocation = {
          ip,
          country: 'LOCAL',
          region: 'LOCAL',
          city: 'Localhost',
          latitude: 0,
          longitude: 0,
          timezone: 'UTC',
          isVPN: false,
          isProxy: false,
          isAnonymous: false
        };
        return localLocation;
      }

      // Lookup IP using geoip-lite
      const geo = geoip.lookup(ip);
      
      if (!geo) {
        console.warn(`No geolocation data found for IP: ${ip}`);
        return null;
      }

      const location: GeoLocation = {
        ip,
        country: geo.country,
        region: geo.region,
        city: geo.city || 'Unknown',
        latitude: geo.ll[0],
        longitude: geo.ll[1],
        timezone: geo.timezone,
      };

      // Check for VPN/Proxy (basic implementation)
      location.isVPN = this.isVPNProvider(ip);
      location.isProxy = this.isProxyProvider(ip);
      location.isAnonymous = location.isVPN || location.isProxy;

      // Cache the result
      this.cache.set(ip, location);

      return location;
    } catch (error) {
      console.error('Geolocation lookup error:', error);
      return null;
    }
  }

  /**
   * Check if IP is local/private
   */
  private isLocalIP(ip: string): boolean {
    return (
      ip === '127.0.0.1' ||
      ip === '::1' ||
      ip === 'localhost' ||
      ip.startsWith('192.168.') ||
      ip.startsWith('10.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.20.') ||
      ip.startsWith('172.21.') ||
      ip.startsWith('172.22.') ||
      ip.startsWith('172.23.') ||
      ip.startsWith('172.24.') ||
      ip.startsWith('172.25.') ||
      ip.startsWith('172.26.') ||
      ip.startsWith('172.27.') ||
      ip.startsWith('172.28.') ||
      ip.startsWith('172.29.') ||
      ip.startsWith('172.30.') ||
      ip.startsWith('172.31.')
    );
  }

  /**
   * Check if IP belongs to known VPN provider
   * TODO: Implement with a proper VPN detection service
   */
  private isVPNProvider(ip: string): boolean {
    // This is a placeholder - in production use a service like:
    // - IPQualityScore API
    // - IP2Location
    // - VPNapi.io
    return false;
  }

  /**
   * Check if IP belongs to known proxy provider
   * TODO: Implement with a proper proxy detection service
   */
  private isProxyProvider(ip: string): boolean {
    // This is a placeholder - in production use a proxy detection service
    return false;
  }

  /**
   * Get multiple locations in batch
   */
  async getBatchLocations(ips: string[]): Promise<Map<string, GeoLocation | null>> {
    const results = new Map<string, GeoLocation | null>();
    
    for (const ip of ips) {
      const location = await this.getLocationFromIP(ip);
      results.set(ip, location);
    }
    
    return results;
  }

  /**
   * Clear cache for specific IP or all
   */
  clearCache(ip?: string): void {
    if (ip) {
      this.cache.del(ip);
    } else {
      this.cache.flushAll();
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return this.cache.getStats();
  }
}

export const geolocationService = new GeolocationService();