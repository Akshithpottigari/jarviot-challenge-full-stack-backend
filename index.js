const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const app = express();
const { google } = require("googleapis");
const GOOGLE_SECRETS = require("./constants");
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:4200",
  })
);

// Creating oauth client
const oauthClient = new google.auth.OAuth2({
  clientId: GOOGLE_SECRETS.web["client_id"],
  clientSecret: GOOGLE_SECRETS.web["client_secret"],
  redirectUri: "http://localhost:3000/loginCallback",
});

// Routes:

app.get("/loginWithGoogle", (req, res) => {
  const auth = oauthClient.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/drive"],
  });

  res.json({ authURL: auth });
});

app.get("/loginCallback", async (req, res) => {
  const { code } = req.query;
  try {
    const { tokens } = await oauthClient.getToken(code);
    const access_token = tokens.access_token;
    const newAccessTokenModel = new AccessTokenModel({
      token: access_token,
    });
    await newAccessTokenModel.save();
    res.redirect("http://localhost:4200/auth/loginSuccess/"+access_token);
  } catch (error) {
    console.error(error);
    res.status(500).json({error: error.message});
  }
});

const getAccessTokenFromHeaders = (req, res, next) => {
  const access_token = req.headers.access_token;
  if(!access_token) {
    res.status(403).json({error:"No access token provided"});
  } else {
    next();
  }
}

const authorizeAccessToken = (req, res, next) => {
  try {
    const oauthClient = new google.auth.OAuth2();
    oauthClient.setCredentials({access_token : req.headers.access_token});
    req.driveClient = google.drive({version : "v3", auth : oauthClient});
    next();
  } catch (error) {
    res.status(500).json({error : "Not valid access token"});
  }
}

app.get("/getRiskReport",getAccessTokenFromHeaders, authorizeAccessToken, async (req, res) => {
  try {
    const result = {
      privateFiles : [],
      files : [],
      sharedFiles : [],
      filesSharedWithMe : [],
      mySharedFiles : [],
      peopleWithFiles : [],
    }
    let pageToken = undefined;
    do {
      const driveClient = await req.driveClient.files.list({
        pageSize: 1000,
        fields: 'nextPageToken, files(id, name, mimeType, size, shared, owners, permissions)',
        pageToken : pageToken
      });
      result.files.push(...driveClient.data.files);
      driveClient.data.files.forEach(file => {
        if(file.shared) {
          // For shared files
          result.sharedFiles.push(file);

          // For categorizing the ownership of a file
          if(file.owners.some(owner => owner.me)){
            result.mySharedFiles.push(file);
          } else {
            result.filesSharedWithMe.push(file);
          }
        } else {
          // For private files
          result.privateFiles.push(file);
        }
      });
      pageToken = driveClient.data.nextPageToken;
    } while (pageToken);
    result.peopleWithFiles = extractPeopleWithFiles(result.sharedFiles);
    let riskCount =  ((result.files.length - result.privateFiles.length) / result.files.length) * 100;
    res.status(200).json({riskCount: riskCount, data : result});
  } catch (error) {
    console.error("Error while processing analytics: "+ error)
    res.status(500).json({error: error});
  }
})

function extractPeopleWithFiles(files) {
  const peopleMap = new Map();

  files.forEach((file) => {
    file.owners.forEach((owner) => {
      const ownerKey = owner.emailAddress;

      if (!peopleMap.has(ownerKey)) {
        peopleMap.set(ownerKey, []);
      }

      peopleMap.get(ownerKey).push(file);
    });
  });

  const peopleWithFiles = Array.from(peopleMap.entries()).map(([person, files]) => ({
    person,
    files,
  }));

  return peopleWithFiles;
}

app.get("/revokeAccess", async (req, res) => {
  try {
    const oauthClient = new google.auth.OAuth2();
    oauthClient.revokeToken(req.headers.access_token);
    await AccessTokenModel.deleteOne({token : req.headers.access_token});
    res.status(200).json({message : "Access token revoked."});
  } catch (error) {
    console.log('error: ', error);
    res.status(500).json({error: "Internal Server Error"});
  }
})

// Models:

const accessTokenSchema = new mongoose.Schema(
  {
    token: {
      type: "string",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

const AccessTokenModel = mongoose.model("AccessToken", accessTokenSchema);

// Connect to MongoDB and staring server
mongoose
  .connect("mongodb://0.0.0.0:27017/google_drive_reports", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
    // Start the server
    app.listen(3000, () => {
      console.log("Server started on port 3000");
    });
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });
