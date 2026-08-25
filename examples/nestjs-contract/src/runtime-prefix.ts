declare const application: { setGlobalPrefix(value: string): void; enableVersioning(): void };

// Runtime bootstrap calls are intentionally not interpreted by static source analysis.
application.setGlobalPrefix('api');
application.enableVersioning();
