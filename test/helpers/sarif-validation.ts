import Ajv from 'ajv';

// Local shape validator shared by legacy and Source-aware SARIF tests; no remote schema fetch.
export const validateLocalSarif = new Ajv({ strict: false }).compile({
  type: 'object', required: ['$schema', 'version', 'runs'],
  properties: {
    version: { const: '2.1.0' },
    runs: {
      type: 'array', minItems: 1,
      items: {
        type: 'object', required: ['tool', 'results'],
        properties: {
          tool: {
            type: 'object', required: ['driver'],
            properties: {
              driver: {
                type: 'object', required: ['name', 'rules'],
                properties: { rules: { type: 'array' } },
              },
            },
          },
          results: {
            type: 'array', items: {
              type: 'object', required: ['ruleId', 'level', 'message', 'partialFingerprints'],
              properties: { level: { enum: ['error', 'warning', 'note'] } },
            },
          },
        },
      },
    },
  },
});
