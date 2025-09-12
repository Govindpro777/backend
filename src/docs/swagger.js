const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');

const setupSwagger = (app) => {
  try {
    const swaggerDocument = YAML.load(path.join(__dirname, 'openapi.yaml'));
    
    const options = {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'Mental Health Platform API',
      swaggerOptions: {
        persistAuthorization: true,
        docExpansion: 'none',
        defaultModelsExpandDepth: -1,
        filter: true,
        showExtensions: true,
        showCommonExtensions: true
      }
    };

    app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, options));
  } catch (error) {
    console.error('Swagger setup failed:', error);
  }
};

module.exports = { setupSwagger };