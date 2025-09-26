import os from 'os';
import packageInfo from '../../package.json';

/**
 * GET /api/health
 *
 * Provides a basic health check with runtime metrics like uptime,
 * memory and cpu usage. Useful for load balancers and monitoring
 * tools to verify that the server is responsive.
 *
 * @returns { status: number, version: string, health: object }
 */
export default defineEventHandler(() => {
  const start: number = Date.now();

  // Gather system information
  const uptime: number = process.uptime();
  const currentTime: string = new Date().toISOString();
  const timezone: string = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const memoryUsage: NodeJS.MemoryUsage = process.memoryUsage();
  const cpuUsage: NodeJS.CpuUsage = process.cpuUsage();
  const freeMemoryPercentage: string = ((os.freemem() / os.totalmem()) * 100).toFixed(2);
  const nodeVersion: string = process.version;

  // Define thresholds for health conditions
  const thresholds = {
    min_uptime: 300, // Minimum 5 minutes (in seconds)
    min_free_memory_percentage: 15, // Minimum 15% free memory
  };

  // Check for health conditions
  const healthIssues = {
    low_memory: parseFloat(freeMemoryPercentage) < thresholds.min_free_memory_percentage,
    short_uptime: uptime < thresholds.min_uptime,
  };

  // Determine health status based on conditions
  const isHealthy: boolean = !healthIssues.low_memory && !healthIssues.short_uptime;
  const healthStatus: 'healthy' | 'unhealthy' = isHealthy ? 'healthy' : 'unhealthy';

  // Uptime breakdown for readability
  const uptimeDays: number = Math.floor(uptime / 86400);
  const uptimeHours: number = Math.floor((uptime % 86400) / 3600);
  const uptimeMinutes: number = Math.floor((uptime % 3600) / 60);
  const uptimeSeconds: number = Math.floor(uptime % 60);

  // Measure response time
  const responseTime: string = `${Date.now() - start} ms`;

  // Structured response
  return {
    status: 200,
    version: packageInfo.version,
    health: {
      status: healthStatus,
      issues: healthIssues,
      thresholds,
    },
    time: {
      current_time: currentTime,
      timezone: timezone,
      uptime: {
        days: uptimeDays,
        hours: uptimeHours,
        minutes: uptimeMinutes,
        seconds: uptimeSeconds,
      },
    },
    memory: {
      total: `${(os.totalmem() / 1024 / 1024).toFixed(2)} MB`,
      free: `${(os.freemem() / 1024 / 1024).toFixed(2)} MB`,
      free_percentage: `${freeMemoryPercentage}%`,
      rss: `${(memoryUsage.rss / 1024 / 1024).toFixed(2)} MB`,
      heap: {
        total: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
        used: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      },
      external: `${(memoryUsage.external / 1024 / 1024).toFixed(2)} MB`,
      array_buffers: `${(memoryUsage.arrayBuffers / 1024 / 1024).toFixed(2)} MB`,
    },
    cpu: {
      count: os.cpus().length,
      user_time: `${(cpuUsage.user / 1000).toFixed(2)} ms`,
      system_time: `${(cpuUsage.system / 1000).toFixed(2)} ms`,
    },
    system: {
      hostname: os.hostname(),
      platform: os.platform(),
      node_version: nodeVersion,
      architecture: os.arch(),
      release: os.release(),
      type: os.type(),
    },
    response_time: responseTime,
  };
});

defineRouteMeta({
  openAPI: {
    operationId: 'getHealth',
    tags: ['Application'],
    summary: 'Application health check',
    description:
      'Returns runtime and system metrics for liveness/monitoring. Useful for load balancers and probes to verify the server responds in time.',
    responses: {
      200: {
        description: 'Health information collected successfully.',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                status: { type: 'number', example: 200 },
                version: { type: 'string', description: 'Application version (from package.json)' },
                health: {
                  type: 'object',
                  properties: {
                    status: { type: 'string', enum: ['healthy', 'unhealthy'] },
                    issues: {
                      type: 'object',
                      properties: {
                        low_memory: { type: 'boolean' },
                        short_uptime: { type: 'boolean' },
                      },
                    },
                    thresholds: {
                      type: 'object',
                      properties: {
                        min_uptime: { type: 'number', description: 'Seconds' },
                        min_free_memory_percentage: { type: 'number', description: 'Percent' },
                      },
                    },
                  },
                  required: ['status', 'issues', 'thresholds'],
                },
                time: {
                  type: 'object',
                  properties: {
                    current_time: { type: 'string', format: 'date-time' },
                    timezone: { type: 'string' },
                    uptime: {
                      type: 'object',
                      properties: {
                        days: { type: 'number' },
                        hours: { type: 'number' },
                        minutes: { type: 'number' },
                        seconds: { type: 'number' },
                      },
                    },
                  },
                },
                memory: {
                  type: 'object',
                  properties: {
                    total: { type: 'string', description: 'e.g. "16384.00 MB"' },
                    free: { type: 'string' },
                    free_percentage: { type: 'string', example: '42.37%' },
                    rss: { type: 'string' },
                    heap: {
                      type: 'object',
                      properties: {
                        total: { type: 'string' },
                        used: { type: 'string' },
                      },
                    },
                    external: { type: 'string' },
                    array_buffers: { type: 'string' },
                  },
                },
                cpu: {
                  type: 'object',
                  properties: {
                    count: { type: 'number' },
                    user_time: { type: 'string', example: '123.45 ms' },
                    system_time: { type: 'string', example: '67.89 ms' },
                  },
                },
                system: {
                  type: 'object',
                  properties: {
                    hostname: { type: 'string' },
                    platform: { type: 'string' },
                    node_version: { type: 'string' },
                    architecture: { type: 'string' },
                    release: { type: 'string' },
                    type: { type: 'string' },
                  },
                },
                response_time: { type: 'string', example: '4 ms' },
              },
              required: ['status', 'version', 'health', 'time', 'memory', 'cpu', 'system', 'response_time'],
            },
            examples: {
              example: {
                summary: 'Typical healthy response',
                value: {
                  status: 200,
                  version: '2025.9.1',
                  health: {
                    status: 'healthy',
                    issues: { low_memory: false, short_uptime: false },
                    thresholds: { min_uptime: 300, min_free_memory_percentage: 15 },
                  },
                  time: {
                    current_time: '2025-02-09T09:26:10.570Z',
                    timezone: 'Europe/Berlin',
                    uptime: { days: 1, hours: 2, minutes: 30, seconds: 5 },
                  },
                  memory: {
                    total: '16384.00 MB',
                    free: '9216.00 MB',
                    free_percentage: '56.25%',
                    rss: '200.50 MB',
                    heap: { total: '150.00 MB', used: '90.00 MB' },
                    external: '10.00 MB',
                    array_buffers: '5.00 MB',
                  },
                  cpu: { count: 8, user_time: '250.00 ms', system_time: '120.00 ms' },
                  system: {
                    hostname: 'svc-01',
                    platform: 'linux',
                    node_version: 'v20.11.1',
                    architecture: 'x64',
                    release: '5.15.0-102',
                    type: 'Linux',
                  },
                  response_time: '3 ms',
                },
              },
            },
          },
        },
      },
      500: { description: 'Unexpected server error while collecting health metrics.' },
    },
  },
});
