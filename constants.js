const GOOGLE_SECRETS = {
  web: {
    client_id:
      "",
    project_id: "",
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_secret: "",
    redirect_uris: [
      "http://localhost:3000/loginCallback",
      "http://localhost",
      "http://localhost:3000",
    ],
    javascript_origins: ["http://localhost", "http://localhost:4200"],
  },
};

module.exports = GOOGLE_SECRETS;