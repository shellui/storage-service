"use strict";

const swaggerSettings = {{ settings|safe }};
const schemaAuthNames = {{ schema_auth_names|safe }};
let schemaAuthFailed = false;
const plugins = [];

const reloadSchemaOnAuthChange = () => {
  return {
    statePlugins: {
      auth: {
        wrapActions: {
          authorizeOauth2:(ori) => (...args) => {
            schemaAuthFailed = false;
            setTimeout(() => ui.specActions.download());
            return ori(...args);
          },
          authorize: (ori) => (...args) => {
            schemaAuthFailed = false;
            setTimeout(() => ui.specActions.download());
            return ori(...args);
          },
          logout: (ori) => (...args) => {
            schemaAuthFailed = false;
            setTimeout(() => ui.specActions.download());
            return ori(...args);
          },
        },
      },
    },
  };
};

if (schemaAuthNames.length > 0) {
  plugins.push(reloadSchemaOnAuthChange);
}

const uiInitialized = () => {
  try {
    ui;
    return true;
  } catch {
    return false;
  }
};

const isSchemaUrl = (url) => {
  if (!uiInitialized()) {
    return false;
  }
  return url === new URL(ui.getConfigs().url, document.baseURI).href;
};

const responseInterceptor = (response, ...args) => {
  if (!response.ok && isSchemaUrl(response.url)) {
    console.warn("schema request received '" + response.status + "'. disabling credentials for schema till logout.");
    if (!schemaAuthFailed) {
      // only retry once to prevent endless loop.
      schemaAuthFailed = true;
      setTimeout(() => ui.specActions.download());
    }
  }
  return response;
};

const injectAuthCredentials = (request) => {
  let authorized;
  if (uiInitialized()) {
    const state = ui.getState().get("auth").get("authorized");
    if (state !== undefined && Object.keys(state.toJS()).length !== 0) {
      authorized = state.toJS();
    }
  } else if (![undefined, "{}"].includes(localStorage.authorized)) {
    authorized = JSON.parse(localStorage.authorized);
  }
  if (authorized === undefined) {
    return;
  }
  for (const authName of schemaAuthNames) {
    const authDef = authorized[authName];
    if (authDef === undefined || authDef.schema === undefined) {
      continue;
    }
    if (authDef.schema.type === "http" && authDef.schema.scheme === "bearer") {
      request.headers["Authorization"] = "Bearer " + authDef.value;
      return;
    } else if (authDef.schema.type === "http" && authDef.schema.scheme === "basic") {
      request.headers["Authorization"] = "Basic " + btoa(authDef.value.username + ":" + authDef.value.password);
      return;
    } else if (authDef.schema.type === "apiKey" && authDef.schema.in === "header") {
      request.headers[authDef.schema.name] = authDef.value;
      return;
    } else if (authDef.schema.type === "oauth2" && authDef.token.token_type === "Bearer") {
      request.headers["Authorization"] = `Bearer ${authDef.token.access_token}`;
      return;
    }
  }
};

const requestInterceptor = (request, ...args) => {
  if (request.loadSpec && schemaAuthNames.length > 0 && !schemaAuthFailed) {
    try {
      injectAuthCredentials(request);
    } catch (e) {
      console.error("schema auth injection failed with error: ", e);
    }
  }
  // selectively omit adding headers to mitigate CORS issues.
  if (!["GET", undefined].includes(request.method) && request.credentials === "same-origin") {
    request.headers["{{ csrf_header_name }}"] = "{{ csrf_token }}";
  }
  return request;
};

const ui = SwaggerUIBundle({
  url: "{{ schema_url|escapejs }}",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis],
  plugins,
  layout: "BaseLayout",
  requestInterceptor,
  responseInterceptor,
  ...swaggerSettings,
});

const getSpecSecuritySchemes = () => {
  try {
    const state = ui.getState();
    const schemes = state.getIn(["spec", "json", "components", "securitySchemes"]);
    return schemes?.toJS?.() ?? {};
  } catch {
    return {};
  }
};

const applyShellUIAccessToken = (token) => {
  if (!token) return false;
  const securitySchemes = getSpecSecuritySchemes();
  const candidateNames = Array.from(
    new Set([...schemaAuthNames, ...Object.keys(securitySchemes)]),
  );
  let applied = false;

  for (const authName of candidateNames) {
    const scheme = securitySchemes[authName];
    if (!scheme) continue;
    if (scheme.type === "http" && String(scheme.scheme).toLowerCase() === "bearer") {
      ui.preauthorizeApiKey(authName, token);
      applied = true;
      continue;
    }
    if (
      scheme.type === "apiKey" &&
      scheme.in === "header" &&
      String(scheme.name).toLowerCase() === "authorization"
    ) {
      ui.preauthorizeApiKey(authName, `Bearer ${token}`);
      applied = true;
    }
  }

  return applied;
};

window.__applyShellUIAccessToken = (token) => {
  if (!token) return;
  if (applyShellUIAccessToken(token)) return;

  // Swagger spec can load asynchronously; retry briefly until schemes are available.
  let attempts = 0;
  const maxAttempts = 30;
  const interval = setInterval(() => {
    attempts += 1;
    if (applyShellUIAccessToken(token) || attempts >= maxAttempts) {
      clearInterval(interval);
    }
  }, 200);
};

window.__applyShellUIAccessToken(window.__shelluiAccessToken);

{% if oauth2_config %}ui.initOAuth({{ oauth2_config|safe }});{% endif %}
