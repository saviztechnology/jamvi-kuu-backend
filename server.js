const express = require('express');
const cors = require('cors');
const axios = require('axios');
const dotenv = require('dotenv');
const cron = require('node-cron');
const admin = require('firebase-admin');
const { cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const bcrypt = require('bcryptjs');
const { getMessaging } = require('firebase-admin/messaging');

const {
  getFirestore,
  FieldValue,
  Timestamp,
} = require('firebase-admin/firestore');

dotenv.config();
const app = express();

const serviceAccount =
  require('./firebase-service-account.json');

admin.initializeApp({
  credential: cert(serviceAccount),
  projectId: 'jamvi-kuu-tips',
});

const db = getFirestore();
const auth = getAuth();

app.use(cors());
app.use(express.json());

// =====================================
// ADMIN AUTH MIDDLEWARE
// =====================================

async function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith('Bearer ')
  ) {
    return res.status(401).json({
      success: false,
      message:
        'Authentication ya admin inahitajika.',
    });
  }

  const idToken =
    authHeader.substring(7);

  try {
    const decodedToken =
      await auth.verifyIdToken(idToken);

    if (decodedToken.admin !== true) {
      return res.status(403).json({
        success: false,
        message:
          'Huna ruhusa ya admin.',
      });
    }

    req.adminUser = decodedToken;

    next();

  } catch (error) {
    console.error(
      'ADMIN AUTH ERROR:',
      error.message,
    );

    return res.status(401).json({
      success: false,
      message:
        'Authentication token si halali.',
    });
  }
}

// =====================================
// JAMVI KUU TIPS - PRIVACY POLICY
// =====================================

app.get('/privacy-policy', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Jamvi Kuu Tips - Privacy Policy</title>

  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.7;
      margin: 0;
      padding: 0;
      background: #080C10;
      color: #ffffff;
    }

    .container {
      max-width: 900px;
      margin: auto;
      padding: 30px 20px;
    }

    h1 {
      color: #00C853;
    }

    h2 {
      color: #00C853;
      margin-top: 30px;
    }

    p, li {
      color: #dddddd;
    }

    .updated {
      color: #999999;
    }

    a {
      color: #00C853;
    }
  </style>
</head>

<body>

<div class="container">

  <h1>Jamvi Kuu Tips - Privacy Policy</h1>

  <p class="updated">
    Last updated: September 25, 2026
  </p>

  <p>
    Jamvi Kuu Tips ("we", "us", or "our") operates the
    Jamvi Kuu Tips mobile application ("App").
  </p>

  <p>
    This Privacy Policy explains how we collect, use, store,
    and protect information when you use the App.
  </p>

  <h2>1. Information We Collect</h2>

  <h3>Account Information</h3>

  <p>When you create an account, we may collect:</p>

  <ul>
    <li>Phone number</li>
    <li>User ID</li>
    <li>Account information</li>
    <li>Account role</li>
    <li>VIP/Premium subscription status</li>
    <li>VIP subscription start and expiry information</li>
  </ul>

  <h3>App and Usage Information</h3>

  <p>
    We may process information related to your use of the App,
    including tips and content you access, Premium features,
    app interactions, and notification-related information.
  </p>

  <h3>Payment Information</h3>

  <p>
    Jamvi Kuu Tips may provide Premium/VIP payments through
    third-party payment services.
  </p>

  <p>
    Payment providers may process payment information according
    to their own privacy policies and terms.
  </p>

  <p>
    We do not intend to store users' complete bank card numbers,
    CVV codes, passwords, or payment authentication codes in
    our own database.
  </p>

  <h3>Advertising Information</h3>

  <p>
    The App may display advertisements using Google AdMob.
    Google and its advertising partners may process information
    such as device or advertising identifiers and information
    related to advertising requests and interactions, subject to
    applicable policies and settings.
  </p>

  <h2>2. How We Use Information</h2>

  <ul>
    <li>Create and manage user accounts</li>
    <li>Authenticate users</li>
    <li>Provide football tips and match information</li>
    <li>Provide Premium/VIP services</li>
    <li>Process and verify Premium payments</li>
    <li>Send notifications</li>
    <li>Display advertisements</li>
    <li>Maintain and improve the App</li>
    <li>Prevent unauthorized access and misuse</li>
    <li>Troubleshoot technical problems</li>
  </ul>

  <h2>3. Firebase Services</h2>

  <p>
    Jamvi Kuu Tips uses Firebase services provided by Google,
    including authentication, database storage, and notifications.
  </p>

  <h2>4. Advertising</h2>

  <p>
    Jamvi Kuu Tips may use Google AdMob to display advertisements.
    Advertisements may be personalized or non-personalized
    depending on applicable settings, consent requirements,
    device settings, and Google's advertising policies.
  </p>

  <h2>5. Data Sharing</h2>

  <p>
    We may share or allow access to information with service
    providers necessary to operate the App, including:
  </p>

  <ul>
    <li>Google Firebase</li>
    <li>Google AdMob</li>
    <li>Payment service providers</li>
    <li>Infrastructure and hosting providers</li>
  </ul>

  <p>
    We do not sell users' personal information as a standalone
    commercial product.
  </p>

  <h2>6. Data Security</h2>

  <p>
    We take reasonable technical and organizational measures
    to protect information against unauthorized access,
    alteration, disclosure, or destruction.
  </p>

  <p>
    However, no internet transmission or electronic storage
    system can be guaranteed to be completely secure.
  </p>

  <h2>7. Data Retention</h2>

  <p>
    We retain information for as long as reasonably necessary
    to provide our services, maintain account records, comply
    with legal obligations, resolve disputes, enforce agreements,
    and maintain security.
  </p>

  <h2>8. Account and Data Deletion</h2>

  <p>
    Users may request deletion of their Jamvi Kuu Tips account
    and associated personal information.
  </p>

  <p>
    To request account deletion, contact the Jamvi Kuu Tips
    support team through the official support contact provided
    with the App.
  </p>

  <p>
    Some information may be retained where required by law,
    for legitimate security purposes, or for resolving
    transactions and disputes.
  </p>

  <h2>9. Children's Privacy</h2>

  <p>
    Jamvi Kuu Tips is not intended to knowingly collect
    personal information from children in violation of
    applicable laws.
  </p>

  <h2>10. Third-Party Services</h2>

  <p>
    The App may use third-party services including Firebase,
    Google AdMob, payment providers, and other services
    required to provide App functionality.
  </p>

  <h2>11. Changes to This Privacy Policy</h2>

  <p>
    We may update this Privacy Policy from time to time.
    When changes are made, the "Last updated" date will be
    updated accordingly.
  </p>

<h2>12. Contact Us</h2>

<p>
  If you have questions about this Privacy Policy, our data
  practices, or account deletion, please contact us using the
  email address below.
</p>

<p>
  <strong>Email:</strong>
  <a href="mailto:support.jamvikuutips@gmail.com">
    support.jamvikuutips@gmail.com
  </a>
</p>

<p>
  <strong>App name:</strong> Jamvi Kuu Tips
</p>

<p>
  <strong>Developer:</strong> thobias mabula
</p>

</div>

</body>
</html>
  `);
});
// =====================================
// JAMVI KUU TIPS - NORMAL USER AUTH
// PHONE + PASSWORD - NO OTP
// =====================================

// -------------------------------------
// FORMAT TANZANIA PHONE NUMBER
// -------------------------------------

function formatTanzaniaPhone(phone) {
  let number = String(phone ?? '').trim();

  // Remove spaces, dashes and brackets
  number = number.replace(/[\s\-()]/g, '');

  if (number.startsWith('0')) {
    number =
      '+255' +
      number.substring(1);
  } else if (
    number.startsWith('255')
  ) {
    number =
      '+' + number;
  } else if (
    !number.startsWith('+')
  ) {
    number =
      '+255' + number;
  }

  return number;
}

// -------------------------------------
// VALIDATE TANZANIA PHONE
// -------------------------------------

function isValidTanzaniaPhone(phone) {
  return /^\+255\d{9}$/.test(phone);
}

// -------------------------------------
// PASSWORD VALIDATION
// -------------------------------------

function isValidPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 6
  );
}

// -------------------------------------
// AUTH CREDENTIAL DOCUMENT ID
// -------------------------------------

function getCredentialDocId(phone) {
  return phone.replace(
    /[^0-9]/g,
    '',
  );
}

// =====================================
// NORMAL USER REGISTER
// PHONE + PASSWORD
// NO OTP
// =====================================

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const {
        name,
        phone,
        password,
      } = req.body;

      if (!name || !phone || !password) {
        return res.status(400).json({
          success: false,
          message:
              'Jina, namba ya simu na password vinahitajika.',
        });
      }

      const cleanName = String(name).trim();
      const formattedPhone =
          formatTanzaniaPhone(phone);

      if (!isValidTanzaniaPhone(formattedPhone)) {
        return res.status(400).json({
          success: false,
          message:
              'Namba ya simu si sahihi. Tumia mfano 0712345678.',
        });
      }

      if (!isValidPassword(password)) {
        return res.status(400).json({
          success: false,
          message:
              'Password lazima iwe na angalau characters 6.',
        });
      }

      console.log(
        'NORMAL USER REGISTER:',
        formattedPhone,
      );

      const credentialId =
          getCredentialDocId(formattedPhone);

      const credentialRef =
          db
            .collection('auth_credentials')
            .doc(credentialId);

      const credentialDoc =
          await credentialRef.get();

      if (credentialDoc.exists) {
        return res.status(409).json({
          success: false,
          message:
              'Namba hii tayari ina akaunti. Tafadhali ingia.',
        });
      }

      let existingFirebaseUser = null;

try {
  existingFirebaseUser =
    await auth.getUserByPhoneNumber(
      formattedPhone,
    );
} catch (error) {
  if (error.code !== 'auth/user-not-found') {
    throw error;
  }
}

// DO NOT TOUCH EXISTING ADMIN
if (existingFirebaseUser) {
  const existingUserDoc =
    await db
      .collection('users')
      .doc(existingFirebaseUser.uid)
      .get();

  const existingUserData =
    existingUserDoc.data() || {};

  if (existingUserData.role === 'admin') {
    return res.status(409).json({
      success: false,
      message:
        'Namba hii ni ya Admin account. Tumia login ya Admin yenye OTP.',
    });
  }

  return res.status(409).json({
    success: false,
    message:
      'Namba hii tayari imesajiliwa.',
  });
}

const passwordHash =
  await bcrypt.hash(
    password,
    12,
  );

const firebaseUser =
  await auth.createUser({
    phoneNumber:
      formattedPhone,

    displayName:
      cleanName,

    disabled:
      false,
  });

const uid =
  firebaseUser.uid;

await credentialRef.set({
  uid:
    uid,

  phoneNumber:
    formattedPhone,

  passwordHash:
    passwordHash,

  createdAt:
    FieldValue.serverTimestamp(),

  updatedAt:
    FieldValue.serverTimestamp(),
});

await db
  .collection('users')
  .doc(uid)
  .set({
    name:
      cleanName,

    phoneNumber:
      formattedPhone,

    role:
      'user',

    plan:
      'FREE',

    paymentStatus:
      'NONE',

    createdAt:
      FieldValue.serverTimestamp(),

    updatedAt:
      FieldValue.serverTimestamp(),
  });

const customToken =
  await auth.createCustomToken(
    uid,
    {
      role: 'user',
    },
  );

console.log(
  'NORMAL USER REGISTERED:',
  uid,
);

return res.status(201).json({
  success: true,

  message:
    'Akaunti imesajiliwa kikamilifu.',

  uid:
    uid,

  customToken:
    customToken,
});

    } catch (error) {
      console.error(
        'NORMAL USER REGISTER ERROR:',
        error,
      );

      return res.status(500).json({
        success: false,
        message:
            'Usajili umeshindikana.',
      });
    }
  },
);

// =====================================
// NORMAL USER LOGIN
// PHONE + PASSWORD
// NO OTP
// =====================================

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const {
        phone,
        password,
      } = req.body;

      // ---------------------------------
      // BASIC VALIDATION
      // ---------------------------------

      if (!phone || !password) {
        return res.status(400).json({
          success: false,
          message:
            'Namba ya simu na password vinahitajika.',
        });
      }

      const formattedPhone =
        formatTanzaniaPhone(phone);

      if (
        !isValidTanzaniaPhone(
          formattedPhone,
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Namba ya simu si sahihi.',
        });
      }

      console.log(
        'NORMAL USER LOGIN:',
        formattedPhone,
      );

      // ---------------------------------
      // FIND CREDENTIAL
      // ---------------------------------

      const credentialId =
        getCredentialDocId(
          formattedPhone,
        );

      const credentialDoc =
        await db
          .collection(
            'auth_credentials',
          )
          .doc(credentialId)
          .get();

      if (!credentialDoc.exists) {
        return res.status(401).json({
          success: false,
          message:
            'Namba au password si sahihi.',
        });
      }

      const credentials =
        credentialDoc.data() || {};

      const uid =
        credentials.uid;

      const passwordHash =
        credentials.passwordHash;

      if (
        !uid ||
        !passwordHash
      ) {
        return res.status(401).json({
          success: false,
          message:
            'Account credentials si sahihi.',
        });
      }

      // ---------------------------------
      // CHECK PASSWORD
      // ---------------------------------

      const passwordMatches =
        await bcrypt.compare(
          password,
          passwordHash,
        );

      if (!passwordMatches) {
        return res.status(401).json({
          success: false,
          message:
            'Namba au password si sahihi.',
        });
      }

      // ---------------------------------
      // GET FIREBASE USER
      // ---------------------------------

      let firebaseUser;

      try {
        firebaseUser =
          await auth.getUser(uid);
      } catch (error) {
        console.error(
          'FIREBASE USER LOOKUP ERROR:',
          error.message,
        );

        return res.status(401).json({
          success: false,
          message:
            'Account haipatikani.',
        });
      }

      // ---------------------------------
      // BLOCK DISABLED ACCOUNT
      // ---------------------------------

      if (
        firebaseUser.disabled
      ) {
        return res.status(403).json({
          success: false,
          message:
            'Account yako imezuiwa.',
        });
      }

      // ---------------------------------
      // READ USER PROFILE
      // ---------------------------------

      const userDoc =
        await db
          .collection('users')
          .doc(uid)
          .get();

      if (!userDoc.exists) {
        return res.status(404).json({
          success: false,
          message:
            'User profile haipatikani.',
        });
      }

      const userData =
        userDoc.data() || {};

      // ---------------------------------
      // NEVER ALLOW NORMAL PASSWORD LOGIN
      // TO TAKE OVER ADMIN
      // ---------------------------------

      if (
        userData.role === 'admin'
      ) {
        return res.status(403).json({
          success: false,
          message:
            'Admin account inatumia Phone + OTP.',
        });
      }

      // ---------------------------------
      // CREATE CUSTOM TOKEN
      // ---------------------------------

      const customToken =
        await auth.createCustomToken(
            uid,
            {
              role: 'user',
            },
          );

      console.log(
        'NORMAL USER LOGIN SUCCESS:',
        uid,
      );

      // ---------------------------------
      // RESPONSE
      // ---------------------------------

      return res.json({
        success: true,

        message:
          'Login imefanikiwa ✅',

        uid:
          uid,

        name:
          userData.name ??
          firebaseUser.displayName ??
          '',

        phoneNumber:
          userData.phoneNumber ??
          formattedPhone,

        role:
          userData.role ??
          'user',

        plan:
          userData.plan ??
          'FREE',

        paymentStatus:
          userData.paymentStatus ??
          'NONE',

        customToken:
          customToken,
      });

    } catch (error) {
      console.error(
        'NORMAL USER LOGIN ERROR:',
        error,
      );

      return res.status(500).json({
        success: false,

        message:
          'Login imeshindikana.',

        error:
          error.message,
      });
    }
  },
);

app.use((req, res, next) => {
  console.log(
    'REQUEST:',
    req.method,
    req.url,
  );

  next();
});

// =====================================
// SELECTED MATCH STORAGE
// =====================================

let selectedMatch = null;
let selectedMatchState = null;

// =====================================
// SELECT MATCH
// =====================================

app.post(
  '/api/football/select-match',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        fixtureId,
        homeTeam,
        awayTeam,
      } = req.body;

      if (!fixtureId) {
        return res.status(400).json({
          success: false,
          message:
            'fixtureId inahitajika',
        });
      }

      if (!homeTeam || !awayTeam) {
        return res.status(400).json({
          success: false,
          message:
            'homeTeam na awayTeam vinahitajika',
        });
      }

      const newFixtureId =
        Number(fixtureId);

      // =====================================
      // SET NEW SELECTED MATCH
      // =====================================

      selectedMatch = {
        fixtureId: newFixtureId,
        homeTeam: homeTeam,
        awayTeam: awayTeam,
        selectedAt:
          new Date().toISOString(),
      };

      // =====================================
      // RESET OLD MATCH STATE
      // =====================================

      selectedMatchState = null;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .delete();

      console.log(
        'OLD MATCH STATE RESET.',
      );

      // =====================================
      // SAVE SELECTED MATCH
      // =====================================

      await db
        .collection('settings')
        .doc('selectedMatch')
        .set({
          fixtureId: newFixtureId,
          homeTeam: homeTeam,
          awayTeam: awayTeam,
          selectedAt:
            FieldValue.serverTimestamp(),
        });

      console.log(
        'SELECTED MATCH SAVED TO FIRESTORE:',
        JSON.stringify(
          selectedMatch,
          null,
          2,
        ),
      );

      // =====================================
      // START AUTOMATIC MONITORING
      // =====================================

      startSelectedMatchMonitoring();

      console.log(
        '▶️ AUTOMATIC MONITORING STARTED.',
      );

      // =====================================
      // RESPONSE
      // =====================================

      res.json({
        success: true,
        message:
          'Match imechaguliwa kikamilifu ✅',
        match: selectedMatch,
      });

    } catch (error) {
      console.error(
        'SELECT MATCH ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,
        message:
          'Kuchagua match kumeshindikana',
        error: error.message,
      });
    }
  },
);
// =====================================
// GET SELECTED MATCH
// =====================================

app.get(
  '/api/football/selected-match',
  (req, res) => {

    if (!selectedMatch) {
      return res.json({
        success: true,
        selected: false,
        message:
          'Hakuna match iliyochaguliwa.',
      });
    }

    res.json({
      success: true,
      selected: true,
      match: selectedMatch,
    });
  },
);

// =====================================
// LOAD SELECTED MATCH FROM FIRESTORE
// =====================================

async function loadSelectedMatch() {
  try {
    const doc = await db
      .collection('settings')
      .doc('selectedMatch')
      .get();

    if (!doc.exists) {
      console.log(
        'SELECTED MATCH: Firestore bado haina match.',
      );

      selectedMatch = null;

      return;
    }

    const data = doc.data();

    if (!data.fixtureId) {
      console.log(
        'SELECTED MATCH: fixtureId haipo.',
      );

      selectedMatch = null;

      return;
    }

    selectedMatch = {
      fixtureId:
        Number(data.fixtureId),

      homeTeam:
        data.homeTeam ?? 'Home',

      awayTeam:
        data.awayTeam ?? 'Away',

      selectedAt:
        data.selectedAt
          ?.toDate?.()
          ?.toISOString() ?? null,
    };

    console.log(
      'SELECTED MATCH LOADED FROM FIRESTORE:',
      JSON.stringify(
        selectedMatch,
        null,
        2,
      ),
    );

  } catch (error) {
    console.error(
      'LOAD SELECTED MATCH ERROR:',
      error.message,
    );
  }
}

// =====================================
// LOAD SELECTED MATCH STATE
// FROM FIRESTORE
// =====================================

async function loadSelectedMatchState() {
  try {
    const doc = await db
      .collection('settings')
      .doc('selectedMatchState')
      .get();

    if (!doc.exists) {
      console.log(
        'SELECTED MATCH STATE: Firestore bado haina state.',
      );

      selectedMatchState = null;

      return;
    }

    const data = doc.data();

    const savedFixtureId =
      Number(data.fixtureId ?? 0);

    // =====================================
    // CHECK STATE BELONGS TO CURRENT MATCH
    // =====================================

    if (
      !selectedMatch ||
      savedFixtureId !==
        selectedMatch.fixtureId
    ) {
      console.log(
        'SELECTED MATCH STATE: State ya zamani ime-ignore kwa sababu fixtureId haifanani.',
      );

      selectedMatchState = null;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .delete();

      return;
    }

    selectedMatchState = {
      fixtureId:
        savedFixtureId,

      homeScore:
        Number(data.homeScore ?? 0),

      awayScore:
        Number(data.awayScore ?? 0),

      status:
        data.status ?? '',
    };

    console.log(
      'SELECTED MATCH STATE LOADED FROM FIRESTORE:',
      JSON.stringify(
        selectedMatchState,
        null,
        2,
      ),
    );

  } catch (error) {
    console.error(
      'LOAD SELECTED MATCH STATE ERROR:',
      error.message,
    );
  }
}

const PORT =
  process.env.PORT || 3000;

// =====================================
// API-FOOTBALL TEST
// =====================================

app.get(
  '/api/football/test',
  async (req, res) => {
    try {
      const apiKey =
        process.env.FOOTBALL_API_KEY;

      if (!apiKey) {
        return res.status(500).json({
          success: false,
          message:
            'FOOTBALL_API_KEY haipo kwenye .env',
        });
      }

      const response =
        await axios.get(
          'https://v3.football.api-sports.io/status',
          {
            headers: {
              'x-apisports-key':
                apiKey,
            },
          },
        );

      console.log(
        'API-FOOTBALL STATUS:',
        JSON.stringify(
          response.data,
          null,
          2,
        ),
      );

      res.json({
        success: true,
        message:
          'API-Football connection imefanikiwa ✅',
        data: response.data,
      });

    } catch (error) {
      console.error(
        'API-FOOTBALL ERROR:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status || 500,
      ).json({
        success: false,
        message:
          'API-Football connection imeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// API-FOOTBALL EPL FIXTURES
// =====================================

app.get(
  '/api/football/epl-fixtures',
  async (req, res) => {
    try {
      const apiKey =
        process.env.FOOTBALL_API_KEY;

      if (!apiKey) {
        return res.status(500).json({
          success: false,
          message:
            'FOOTBALL_API_KEY haipo kwenye .env',
        });
      }

      const response =
        await axios.get(
          'https://v3.football.api-sports.io/fixtures',
          {
            params: {
              league: 39,
              season: 2026,
            },
            headers: {
              'x-apisports-key':
                apiKey,
            },
          },
        );

      const matches =
        response.data.response || [];

      const fixtures =
        matches.map((match) => ({
          fixtureId:
            match.fixture?.id,

          date:
            match.fixture?.date,

          status:
            match.fixture?.status?.short,

          league:
            match.league?.name,

          homeTeam:
            match.teams?.home?.name,

          awayTeam:
            match.teams?.away?.name,
        }));

      console.log(
        `EPL FIXTURES FOUND: ${fixtures.length}`,
      );

      res.json({
        success: true,
        count: fixtures.length,
        fixtures: fixtures,
      });

    } catch (error) {
      console.error(
        'EPL FIXTURES ERROR:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status || 500,
      ).json({
        success: false,
        message:
          'EPL fixtures zimeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// FLUTTERWAVE OAUTH ACCESS TOKEN
// =====================================

async function getFlutterwaveAccessToken() {
  const response =
    await axios.post(
      'https://idp.flutterwave.com/realms/flutterwave/protocol/openid-connect/token',
      new URLSearchParams({
        client_id:
          process.env.FLW_CLIENT_ID,

        client_secret:
          process.env.FLW_CLIENT_SECRET,

        grant_type:
          'client_credentials',
      }),
      {
        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',
        },
      },
    );

  return response.data.access_token;
}
(async () => {
  try {
    const token = await getFlutterwaveAccessToken();

    console.log('FLUTTERWAVE TOKEN: SUCCESS');
    console.log('TOKEN EXISTS:', !!token);
  } catch (error) {
    console.error(
      'FLUTTERWAVE TOKEN ERROR:',
      error.response?.status,
      error.response?.data || error.message
    );
  }
})();

// =====================================
// HOME
// =====================================

app.get('/', (req, res) => {
  res.json({
    message:
      'Jamvi Kuu Tips Backend iko tayari 🚀',
  });
});

app.get('/api/ping', (req, res) => {
  res.json({
    success: true,
    message:
      'Backend connection iko sawa ✅',
  });
});

// =====================================
// TEST PUSH NOTIFICATION
// DEVICE MOJA
// =====================================

app.post(
  '/api/notification/test',
  async (req, res) => {
    try {
      const {
        token,
        title,
        body,
      } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          message:
            'FCM token inahitajika',
        });
      }

      const message = {
        token: token,

        notification: {
          title:
            title ??
            'Jamvi Kuu Tips 🔥',

          body:
            body ??
            'Tips za leo zipo tayari! Fungua app kuangalia.',
        },

        android: {
          priority: 'high',

          notification: {
            sound: 'default',
          },
        },

        apns: {
          payload: {
            aps: {
              sound: 'default',
              badge: 1,
            },
          },
        },
      };

      const response =
        await getMessaging()
          .send(message);

      console.log(
        'TEST NOTIFICATION SENT:',
        response,
      );

      res.json({
        success: true,
        message:
          'Test notification imetumwa kwenye device hii ✅',
        messageId: response,
      });

    } catch (error) {
      console.error(
        'TEST NOTIFICATION ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,
        message:
          'Test notification imeshindikana',
        error: error.message,
      });
    }
  },
);

// =====================================
// NEW TIP NOTIFICATION
// =====================================

app.post(
  '/api/notification/new-tip',
  async (req, res) => {
    try {
      const {
        title,
        body,
        token,
      } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          message:
            'FCM token inahitajika',
        });
      }

      const response =
        await getMessaging().send({
          token: token,

          notification: {
            title:
              title ||
              '🔥 Jamvi Kuu Tips',

            body:
              body ||
              'Tip mpya imeongezwa!',
          },

          android: {
            priority: 'high',

            notification: {
              sound: 'default',
            },
          },
        });

      console.log(
        'NEW TIP NOTIFICATION SENT:',
        response,
      );

      res.json({
        success: true,
        message:
          'Notification imetumwa ✅',
        messageId: response,
      });

    } catch (error) {
      console.error(
        'NEW TIP NOTIFICATION ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  },
);

// =====================================
// NOTIFY ALL USERS - NEW TIP
// =====================================

app.post(
  '/api/notification/new-tip-all',
  async (req, res) => {
    try {
      const {
        access,
        homeTeam,
        awayTeam,
      } = req.body;

      console.log(
        'NEW TIP ALL USERS:',
        {
          access,
          homeTeam,
          awayTeam,
        },
      );
      const notificationsEnabled =
  await areNotificationsEnabled();

if (!notificationsEnabled) {
  console.log(
    '🔕 NOTIFICATIONS ZIMEZIMWA KUPITIA ADMIN SETTINGS.',
  );

  return res.json({
    success: false,
    notificationsEnabled: false,
    message:
      'Notifications zimezimwa na Admin Settings.',
    sent: 0,
  });
}

      const usersSnapshot =
        await db
          .collection('users')
          .get();

      const tokens = [];

      usersSnapshot.forEach(
        (doc) => {
          const data =
            doc.data();

          if (
            data.fcmToken &&
            typeof data.fcmToken ===
              'string' &&
            data.fcmToken
              .trim() !== ''
          ) {
            tokens.push(
              data.fcmToken.trim(),
            );
          }
        },
      );

      console.log(
        `FCM TOKENS FOUND: ${tokens.length}`,
      );

      if (tokens.length === 0) {
        return res.json({
          success: false,
          message:
            'Hakuna FCM tokens zilizopatikana.',
          sent: 0,
        });
      }

      let title;
      let body;

      if (access === 'VIP') {
        title =
          '👑 VIP TIP MPYA!';

        body =
          'Tip mpya ya VIP imeongezwa. Fungua Jamvi Kuu Tips kuiona 🔥';
      } else {
        title =
          '🔥 TIP MPYA!';

        body =
          `${homeTeam ?? 'Match'} vs ${awayTeam ?? ''} — Tip mpya imeongezwa. Fungua app kuiona.`;
      }

      let sent = 0;
      let failed = 0;

      for (
        let i = 0;
        i < tokens.length;
        i += 500
      ) {
        const batch =
          tokens.slice(i, i + 500);

        const response =
          await getMessaging()
            .sendEachForMulticast({
              tokens: batch,

              notification: {
                title: title,
                body: body,
              },

              android: {
                priority: 'high',

                notification: {
                  sound: 'default',
                },
              },

              apns: {
                payload: {
                  aps: {
                    sound: 'default',
                    badge: 1,
                  },
                },
              },
            });

        sent +=
          response.successCount;

        failed +=
          response.failureCount;
      }

      console.log(
        `NOTIFICATION RESULT: SENT=${sent}, FAILED=${failed}`,
      );

      res.json({
        success: true,
        message:
          'Notification imetumwa kwa users wote ✅',

        totalTokens:
          tokens.length,

        sent: sent,
        failed: failed,
      });

    } catch (error) {
      console.error(
        'NEW TIP ALL USERS ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  },
);

async function areNotificationsEnabled() {
  try {
    const settingsDoc = await db
      .collection('app_settings')
      .doc('general')
      .get();

    if (!settingsDoc.exists) {
      return true;
    }

    const data = settingsDoc.data() || {};

    return data.notificationsEnabled !== false;
  } catch (error) {
    console.error(
      'NOTIFICATION SETTINGS ERROR:',
      error.message,
    );

    // Ikiwa Firestore settings haijasomeka,
    // notification itaendelea kutumwa.
    return true;
  }
}

// =====================================
// TEST FIREBASE FIRESTORE
// =====================================

app.get(
  '/api/test',
  async (req, res) => {
    try {
      const testDoc =
        await db
          .collection('backend_test')
          .doc('status')
          .get();

      res.json({
        success: true,
        firebase: true,
        message:
          'Backend imeunganishwa na Firebase Firestore ✅',
        documentExists:
          testDoc.exists,
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          'Imeshindikana kuwasiliana na Firestore',
      });
    }
  },
);

// =====================================
// TEST FLUTTERWAVE OAUTH
// =====================================

app.get(
  '/api/flutterwave-token-test',
  async (req, res) => {
    try {
      const token =
        await getFlutterwaveAccessToken();

      res.json({
        success: true,
        message:
          'Flutterwave OAuth imefanikiwa ✅',
        tokenReceived:
          !!token,
      });

    } catch (error) {
      console.error(
        'Flutterwave OAuth error:',
        error.response?.data ||
          error.message,
      );

      res.status(500).json({
        success: false,
        message:
          'Flutterwave OAuth imeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// TEST FLUTTERWAVE CUSTOMER
// =====================================

app.post(
  '/api/flutterwave-customer-test',
  async (req, res) => {
    try {
      const {
        email,
        name,
        phone,
      } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message:
            'Email inahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();

      const response =
        await axios.post(
          'https://developersandbox-api.flutterwave.com/customers',
          {
            email: email,

            name:
              name ?? {
                first: 'Jamvi',
                last: 'Kuu',
              },

            phone:
              phone ?? {
                country_code:
                  '255',
                number:
                  '700000000',
              },
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviTrace${Date.now()}`,

              'X-Idempotency-Key':
                `jamviCustomer${Date.now()}`,
            },
          },
        );

      res.status(201).json({
        success: true,
        message:
          'Flutterwave Customer ameundwa ✅',
        data:
          response.data,
      });

    } catch (error) {
      console.error(
        'Flutterwave customer error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,
        message:
          'Customer creation imeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// TEST FLUTTERWAVE MOBILE MONEY
// =====================================

app.post(
  '/api/flutterwave-payment-method-test',
  async (req, res) => {
    try {
      const {
        country_code,
        network,
        phone_number,
      } = req.body;

      if (
        !country_code ||
        !network ||
        !phone_number
      ) {
        return res.status(400).json({
          success: false,
          message:
            'country_code, network na phone_number vinahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();

      const response =
        await axios.post(
          'https://developersandbox-api.flutterwave.com/payment-methods',
          {
            type:
              'mobile_money',

            mobile_money: {
              country_code:
                country_code,

              network:
                network,

              phone_number:
                phone_number,
            },
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviTrace${Date.now()}`,

              'X-Idempotency-Key':
                `jamviMethod${Date.now()}`,
            },
          },
        );

      res.status(201).json({
        success: true,
        message:
          'Mobile Money Payment Method imeundwa ✅',
        data:
          response.data,
      });

    } catch (error) {
      console.error(
        'Flutterwave payment method error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,
        message:
          'Payment Method creation imeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// TEST FLUTTERWAVE CHARGE
// =====================================

app.post(
  '/api/flutterwave-charge-test',
  async (req, res) => {
    try {
      const {
        customer_id,
        payment_method_id,
        amount,
        firebase_uid,
        plan,
      } = req.body;

      if (
        !customer_id ||
        !payment_method_id ||
        !amount
      ) {
        return res.status(400).json({
          success: false,
          message:
            'customer_id, payment_method_id na amount vinahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();

      const response =
        await axios.post(
          'https://developersandbox-api.flutterwave.com/charges',
          {
            customer_id:
              customer_id,

            payment_method_id:
              payment_method_id,

            amount:
              amount,

            currency:
              'TZS',

            reference:
              `JAMVI-${Date.now()}`,

            meta: {
              firebase_uid:
                firebase_uid,

              plan:
                plan ??
                'MONTHLY',
            },
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviCharge${Date.now()}`,

              'X-Idempotency-Key':
                `jamviChargeKey${Date.now()}`,
            },
          },
        );

      res.status(201).json({
        success: true,
        message:
          'Flutterwave Charge imeundwa ✅',
        data:
          response.data,
      });

    } catch (error) {
      console.error(
        'Flutterwave charge error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,
        message:
          'Charge creation imeshindikana',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// CHECK FLUTTERWAVE CHARGE STATUS
// =====================================

app.get(
  '/api/flutterwave-charge-status/:chargeId',
  async (req, res) => {
    try {
      const {
        chargeId,
      } = req.params;

      if (!chargeId) {
        return res.status(400).json({
          success: false,
          message:
            'chargeId inahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();

      const response =
        await axios.get(
          `https://developersandbox-api.flutterwave.com/charges/${chargeId}`,
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviStatus${Date.now()}`,
            },
          },
        );

      res.json({
        success: true,
        message:
          'Charge status imepatikana ✅',
        data:
          response.data,
      });

    } catch (error) {
      console.error(
        'Flutterwave charge status error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,
        message:
          'Imeshindikana kupata charge status',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// INITIATE FLUTTERWAVE PAYMENT
// =====================================

app.post(
  '/api/payment/initiate',
  async (req, res) => {
    try {
      const {
        amount,
        phone_number,
        email,
        tx_ref,
        fullname,
        firebase_uid,
        plan,
        network,
      } = req.body;

      if (
        !amount ||
        !phone_number ||
        !email ||
        !tx_ref ||
        !firebase_uid
      ) {
        return res.status(400).json({
          success: false,
          message:
            'amount, phone_number, email, tx_ref na firebase_uid vinahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();

      // =====================================
      // SEARCH CUSTOMER
      // =====================================

      console.log('STEP 1: SEARCH CUSTOMER');
      const customerSearchResponse =
        await axios.get(
          'https://developersandbox-api.flutterwave.com/customers',
          {
            params: {
              email:
                email,
            },

            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviCustomerSearch${Date.now()}`,
            },
          },
        );

      let customerId;

      const customers =
        customerSearchResponse
          .data.data;

console.log('STEP 1 OK: CUSTOMER SEARCH');
      if (
        customers &&
        customers.length > 0
      ) {
        customerId =
          customers[0].id;

        console.log(
          'CUSTOMER EXISTING:',
          customerId,
        );

      } else {

        const customerResponse =
          await axios.post(
            'https://developersandbox-api.flutterwave.com/customers',
            {
              email:
                email,

              name: {
                first:
                  'Jamvi',

                last:
                  'Kuu',
              },

              phone: {
                country_code:
                  '255',

                number:
                  phone_number
                    .replace(
                      '+255',
                      '',
                    ),
              },
            },
            {
              headers: {
                Authorization:
                  `Bearer ${token}`,

                'Content-Type':
                  'application/json',

                'X-Trace-Id':
                  `jamviCustomer${Date.now()}`,

                'X-Idempotency-Key':
                  `jamviCustomerKey${Date.now()}`,
              },
            },
          );

        customerId =
          customerResponse
            .data.data.id;

        console.log(
          'CUSTOMER NEW:',
          customerId,
        );
      }

      // =====================================
      // MOBILE MONEY PAYMENT METHOD
      // =====================================

      console.log('STEP 2: CREATE PAYMENT METHOD');
      const paymentMethodResponse =
        await axios.post(
          'https://developersandbox-api.flutterwave.com/payment-methods',
          {
            type:
              'mobile_money',

            mobile_money: {
              country_code:
                '255',

              network:
                network ??
                'AIRTEL',

              phone_number:
                phone_number
                  .replace(
                    '+255',
                    '',
                  ),
            },
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviMethod${Date.now()}`,

              'X-Idempotency-Key':
                `jamviMethodKey${Date.now()}`,
            },
          },
        );

console.log('STEP 2 OK: PAYMENT METHOD');
      const paymentMethodId =
        paymentMethodResponse
          .data.data.id;

      // =====================================
      // CREATE CHARGE
      // =====================================

      console.log('STEP 3: CREATE CHARGE');
      const chargeResponse =
        await axios.post(
          'https://developersandbox-api.flutterwave.com/charges',
          {
            customer_id:
              customerId,

            payment_method_id:
              paymentMethodId,

            amount:
              amount,

            currency:
              'TZS',

            reference:
              tx_ref,

            meta: {
              firebase_uid:
                firebase_uid,

              plan:
                plan ??
                'MONTHLY',
            },
          },
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviCharge${Date.now()}`,

              'X-Idempotency-Key':
                `jamviChargeKey${Date.now()}`,

              'X-Scenario-Key':
                'scenario:auth_redirect',
            },
          },
        );

console.log('STEP 3 OK: CHARGE CREATED');
      const charge =
        chargeResponse.data.data;

      console.log(
        'CHARGE ID:',
        charge.id,
      );

      console.log(
        'CHARGE STATUS:',
        charge.status,
      );

      console.log(
        'NEXT ACTION:',
        JSON.stringify(
          charge.next_action,
          null,
          2,
        ),
      );

      res.status(201).json({
        success: true,

        message:
          'Payment imeanzishwa. Tafadhali authorize kwenye simu yako.',

        customer_id:
          customerId,

        payment_method_id:
          paymentMethodId,

        charge_id:
          charge.id,

        amount:
          charge.amount,

        currency:
          charge.currency,

        status:
          charge.status,

        reference:
          charge.reference,

        plan:
          plan ??
          'MONTHLY',

        payment_instruction:
          charge.next_action
            ?.payment_instruction
            ?.note ??
          'Fuata maelekezo ya malipo kwenye simu yako.',

        redirect_url:
          charge.next_action
            ?.redirect_url
            ?.url ??
          null,
      });

    } catch (error) {
      console.error(
        'Flutterwave payment initiate error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,
        message:
          'Imeshindikana kuanzisha malipo',
        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// FLUTTERWAVE WEBHOOK
// =====================================

app.post(
  '/api/flutterwave-webhook',
  async (req, res) => {
    try {
      const signature =
        req.headers[
          'flutterwave-signature'
        ];

      console.log(
        'Flutterwave webhook imepokelewa',
      );

      console.log(
        'Webhook signature:',
        signature,
      );

      console.log(
        'Webhook body:',
        JSON.stringify(
          req.body,
          null,
          2,
        ),
      );

      res.sendStatus(200);

    } catch (error) {
      console.error(
        'Webhook error:',
        error.message,
      );

      res.sendStatus(500);
    }
  },
);

// =====================================
// ONE-TIME PAYMENT HISTORY MIGRATION
// =====================================

app.post(
  '/api/admin/migrate-old-payment',
  async (req, res) => {
    return res.status(410).json({
      success: false,
      message: 'Migration endpoint imefungwa.',
    });
  },
);
// =====================================
// VERIFY PAYMENT NA KUMPA USER VIP
// =====================================

app.get(
  '/api/payment/verify/:chargeId',
  async (req, res) => {
    
        const authHeader = req.headers.authorization;

    if (!authHeader ||
        !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authentication inahitajika.',
      });
    }

    const idToken =
      authHeader.split('Bearer ')[1];

    let decodedToken;

    try {
      decodedToken =
        await auth.verifyIdToken(idToken);
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Authentication token si halali.',
      });
    }
    try {
      const {
        chargeId,
      } = req.params;

      if (!chargeId) {
        return res.status(400).json({
          success: false,
          message:
            'chargeId inahitajika',
        });
      }

      const token =
        await getFlutterwaveAccessToken();
        console.log('FLUTTERWAVE TOKEN OK');

      const response =
        await axios.get(
          `https://developersandbox-api.flutterwave.com/charges/${chargeId}`,
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',

              'X-Trace-Id':
                `jamviVerify${Date.now()}`,
            },
          },
        );

      const charge =
        response.data.data;

      console.log(
        'VERIFY CHARGE:',
        JSON.stringify(
          charge,
          null,
          2,
        ),
      );

      // =====================================
      // PAYMENT MUST BE SUCCEEDED
      // =====================================

      if (
        charge.status !==
        'succeeded'
      ) {
        return res.json({
          success: false,
          message:
            'Payment bado haijafanikiwa',
          status:
            charge.status,
        });
      }

      // =====================================
      // USER + PLAN
      // =====================================

      const firebaseUid =
        charge.meta
          ?.firebase_uid;

      const plan =
        charge.meta?.plan;

      if (!firebaseUid) {
  return res.status(400).json({
    success: false,
    message:
      'Firebase UID haipo kwenye payment',
  });
}

// =====================================
// CHECK PAYMENT OWNERSHIP
// =====================================

if (decodedToken.uid !== firebaseUid) {
  return res.status(403).json({
    success: false,
    message:
      'Huna ruhusa ya kuthibitisha payment hii.',
  });
}
      if (!plan) {
        return res.status(400).json({
          success: false,
          message:
            'Plan haipo kwenye payment',
        });
      }

      // =====================================
      // MONTHLY ONLY
      // =====================================

      if (
        plan !== 'MONTHLY'
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Kwa sasa tunakubali MONTHLY pekee',
        });
      }

      // =====================================
      // AMOUNT
      // =====================================

      const expectedAmount =
        5000;

      if (
        Number(charge.amount) !==
        expectedAmount
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Amount ya payment haiendani na MONTHLY plan',

          expectedAmount:
            expectedAmount,

          receivedAmount:
            charge.amount,
        });
      }

      // =====================================
      // CURRENCY
      // =====================================

      if (
        charge.currency !==
        'TZS'
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Currency ya payment si TZS',

          receivedCurrency:
            charge.currency,
        });
      }

      // =====================================
      // CHECK DUPLICATE PAYMENT
      // =====================================

      const existingPayment =
        await db
          .collection('payments')
          .doc(charge.id)
          .get();

      if (
        existingPayment.exists
      ) {
        console.log(
          'PAYMENT ALREADY PROCESSED:',
          charge.id,
        );

        return res.json({
          success: true,
          alreadyProcessed: true,

          message:
            'Payment hii tayari ilishathibitishwa.',

          uid:
            firebaseUid,

          plan:
            'MONTHLY',

          amount:
            charge.amount,

          status:
            charge.status,
        });
      }

      // =====================================
      // CREATE VIP DATES
      // =====================================

      const startDate =
        new Date();

      const expiryDate =
        new Date(
          startDate,
        );

      expiryDate.setMonth(
        expiryDate.getMonth() + 1,
      );

      console.log(
        'PREMIUM START DATE:',
        startDate,
      );

      console.log(
        'PREMIUM EXPIRY DATE:',
        expiryDate,
      );

      // =====================================
      // UPDATE USER VIP
      // =====================================

      await db
        .collection('users')
        .doc(firebaseUid)
        .set(
          {
            plan:
              'VIP',

            paymentStatus:
              'PAID',

            premiumStartDate:
              Timestamp.fromDate(
                startDate,
              ),

            premiumExpiryDate:
              Timestamp.fromDate(
                expiryDate,
              ),

            lastPaymentId:
              charge.id,

            lastPaymentReference:
              charge.reference,

            lastPaymentAmount:
              charge.amount,

            lastPaymentCurrency:
              charge.currency,

            updatedAt:
              FieldValue.serverTimestamp(),
          },
          {
            merge: true,
          },
        );

      // =====================================
      // SAVE PAYMENT HISTORY
      // =====================================

      await db
        .collection('payments')
        .doc(charge.id)
        .set(
          {
            userId:
              firebaseUid,

            phoneNumber:
              charge.customer
                ?.phone_number ??
              '',

            amount:
              charge.amount,

            currency:
              charge.currency,

            plan:
              plan,

            paymentStatus:
              'PAID',

            paymentId:
              charge.id,

            reference:
              charge.reference,

            premiumStartDate:
              Timestamp.fromDate(
                startDate,
              ),

            premiumExpiryDate:
              Timestamp.fromDate(
                expiryDate,
              ),

            createdAt:
              FieldValue.serverTimestamp(),
          },
          {
            merge: true,
          },
        );

      console.log(
        'PAYMENT HISTORY SAVED:',
        charge.id,
      );

      // =====================================
// PAYMENT SUCCESS NOTIFICATION
// =====================================

try {
  const userDoc =
    await db
      .collection('users')
      .doc(firebaseUid)
      .get();

  const userData =
    userDoc.data();

  const fcmToken =
    userData?.fcmToken;

  if (fcmToken) {
    const notificationsEnabled =
      await areNotificationsEnabled();

    if (notificationsEnabled) {
      const notificationResponse =
        await getMessaging().send({
          token: fcmToken,

          notification: {
            title:
              '💳 Malipo Yamefanikiwa!',

            body:
              'VIP yako imewashwa kwa mwezi mmoja. Karibu Jamvi Kuu Tips 👑🔥',
          },

          android: {
            priority:
              'high',

            notification: {
              sound:
                'default',
            },
          },

          apns: {
            payload: {
              aps: {
                sound:
                  'default',

                badge:
                  1,
              },
            },
          },
        });

      console.log(
        'PAYMENT SUCCESS NOTIFICATION SENT:',
        notificationResponse,
      );
    } else {
      console.log(
        '🔕 PAYMENT SUCCESS NOTIFICATION IMEZIMWA.',
      );
    }
  } else {
    console.log(
      'PAYMENT SUCCESS NOTIFICATION: FCM TOKEN HAIPO',
    );
  }
} catch (notificationError) {
  console.error(
    'PAYMENT SUCCESS NOTIFICATION ERROR:',
    notificationError.message,
  );
}

      // =====================================
      // SUCCESS RESPONSE
      // =====================================

      res.json({
        success: true,

        message:
          'Payment imethibitishwa na user amepewa VIP kwa mwezi mmoja 🎉',

        uid:
          firebaseUid,

        plan:
          'MONTHLY',

        vipPlan:
          'VIP',

        amount:
          charge.amount,

        currency:
          charge.currency,

        status:
          charge.status,

        premiumStartDate:
          startDate.toISOString(),

        premiumExpiryDate:
          expiryDate.toISOString(),
      });

    } catch (error) {
      console.error(
        'Payment verification error:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,

        message:
          'Payment verification imeshindikana',

        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// VIP EXPIRY REMINDER
// =====================================

app.post(
  '/api/notification/vip-expiry-reminder',
  async (req, res) => {
    try {
      console.log(
        'VIP EXPIRY REMINDER STARTED...',
      );
      const notificationsEnabled =
  await areNotificationsEnabled();

if (!notificationsEnabled) {
  console.log(
    '🔕 VIP EXPIRY NOTIFICATIONS ZIMEZIMWA.',
  );

  return res.json({
    success: false,
    notificationsEnabled: false,
    message:
      'Notifications zimezimwa na Admin Settings.',
    sent: 0,
  });
}

      const now =
        new Date();

      const usersSnapshot =
        await db
          .collection('users')
          .where(
            'plan',
            '==',
            'VIP',
          )
          .get();

      console.log(
        `VIP USERS FOUND: ${usersSnapshot.size}`,
      );

      let remindersSent = 0;
      let skipped = 0;
      let failed = 0;

      for (
        const doc of
          usersSnapshot.docs
      ) {
        try {
          const userData =
            doc.data();

          const expiryTimestamp =
            userData.premiumExpiryDate;

          if (!expiryTimestamp) {
            skipped++;
            continue;
          }

          const expiryDate =
            expiryTimestamp.toDate();

          const differenceMs =
            expiryDate.getTime() -
            now.getTime();

          const differenceDays =
            Math.ceil(
              differenceMs /
                (1000 *
                  60 *
                  60 *
                  24),
            );

          console.log(
            `USER ${doc.id}: expiry=${expiryDate.toISOString()}, days=${differenceDays}`,
          );

          if (
            differenceDays !== 3 &&
            differenceDays !== 1
          ) {
            skipped++;
            continue;
          }

          const fcmToken =
            userData.fcmToken;

          if (!fcmToken) {
            console.log(
              `FCM TOKEN HAIPO: ${doc.id}`,
            );

            skipped++;
            continue;
          }

          let title;
          let body;

          if (
            differenceDays === 3
          ) {
            title =
              '⏰ VIP Yako Inaelekea Kuisha';

            body =
              'VIP yako itaisha baada ya siku 3. Renew sasa ili usikose tips za VIP 👑🔥';

          } else {
            title =
              '🚨 VIP Yako Inaisha Kesho!';

            body =
              'VIP subscription yako inaisha kesho. Renew sasa ili uendelee kupata tips za VIP 👑🔥';
          }

          await getMessaging()
            .send({
              token:
                fcmToken,

              notification: {
                title:
                  title,

                body:
                  body,
              },

              android: {
                priority:
                  'high',

                notification: {
                  sound:
                    'default',
                },
              },

              apns: {
                payload: {
                  aps: {
                    sound:
                      'default',

                    badge:
                      1,
                  },
                },
              },
            });

          remindersSent++;

          console.log(
            `VIP EXPIRY REMINDER SENT: ${doc.id}`,
          );

        } catch (
          userError
        ) {
          failed++;

          console.error(
            `VIP REMINDER ERROR FOR ${doc.id}:`,
            userError.message,
          );
        }
      }

      console.log(
        `VIP EXPIRY RESULT: SENT=${remindersSent}, SKIPPED=${skipped}, FAILED=${failed}`,
      );

      res.json({
        success: true,

        message:
          'VIP expiry reminders zimekamilika ✅',

        vipUsers:
          usersSnapshot.size,

        sent:
          remindersSent,

        skipped:
          skipped,

        failed:
          failed,
      });

    } catch (error) {
      console.error(
        'VIP EXPIRY REMINDER ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,

        message:
          'VIP expiry reminder imeshindikana',

        error:
          error.message,
      });
    }
  },
);

// =====================================
// AUTOMATIC VIP EXPIRY SCHEDULER
// =====================================

cron.schedule(
  '0 9 * * *',
  async () => {
    try {
      console.log(
        '⏰ AUTOMATIC VIP EXPIRY CHECK STARTED...',
      );

      const usersSnapshot =
        await db
          .collection('users')
          .where(
            'plan',
            '==',
            'VIP',
          )
          .get();

      const now =
        new Date();

      let remindersSent = 0;
      let skipped = 0;
      let failed = 0;

      for (
        const doc of
          usersSnapshot.docs
      ) {
        try {
          const userData =
            doc.data();

          const expiryTimestamp =
            userData.premiumExpiryDate;

          if (!expiryTimestamp) {
            skipped++;
            continue;
          }

          const expiryDate =
            expiryTimestamp.toDate();

          const differenceMs =
            expiryDate.getTime() -
            now.getTime();

          const differenceDays =
            Math.ceil(
              differenceMs /
                (1000 *
                  60 *
                  60 *
                  24),
            );

          console.log(
            `AUTO CHECK ${doc.id}: days=${differenceDays}`,
          );

          if (
            differenceDays !== 3 &&
            differenceDays !== 1
          ) {
            skipped++;
            continue;
          }

          const fcmToken =
            userData.fcmToken;

          if (!fcmToken) {
            console.log(
              `FCM TOKEN HAIPO: ${doc.id}`,
            );

            skipped++;
            continue;
          }

          let title;
          let body;

          if (
            differenceDays === 3
          ) {
            title =
              '⏰ VIP Yako Inaelekea Kuisha';

            body =
              'VIP yako itaisha baada ya siku 3. Renew sasa ili usikose tips za VIP 👑🔥';

          } else {
            title =
              '🚨 VIP Yako Inaisha Kesho!';

            body =
              'VIP subscription yako inaisha kesho. Renew sasa ili uendelee kupata tips za VIP 👑🔥';
          }

          await getMessaging()
            .send({
              token:
                fcmToken,

              notification: {
                title:
                  title,

                body:
                  body,
              },

              android: {
                priority:
                  'high',

                notification: {
                  sound:
                    'default',
                },
              },

              apns: {
                payload: {
                  aps: {
                    sound:
                      'default',

                    badge:
                      1,
                  },
                },
              },
            });

          remindersSent++;

          console.log(
            `AUTO VIP REMINDER SENT: ${doc.id}`,
          );

        } catch (
          userError
        ) {
          failed++;

          console.error(
            `AUTO VIP REMINDER ERROR FOR ${doc.id}:`,
            userError.message,
          );
        }
      }

      console.log(
        `⏰ AUTO VIP RESULT: SENT=${remindersSent}, SKIPPED=${skipped}, FAILED=${failed}`,
      );

    } catch (error) {
      console.error(
        'AUTO VIP EXPIRY CHECK ERROR:',
        error.message,
      );
    }
  },
);

// =====================================
// MATCH / LIVE ALERT - ALL USERS
// =====================================

app.post(
  '/api/notification/match-alert',
  async (req, res) => {
    try {
      const {
        title,
        body,
      } = req.body;

      console.log(
        'MATCH ALERT STARTED...',
      );

      console.log({
        title,
        body,
      });

      const notificationsEnabled =
  await areNotificationsEnabled();

if (!notificationsEnabled) {
  console.log(
    '🔕 NOTIFICATIONS ZIMEZIMWA KUPITIA ADMIN SETTINGS.',
  );

  return res.json({
    success: false,
    notificationsEnabled: false,
    message:
      'Notifications zimezimwa na Admin Settings.',
    sent: 0,
  });
}

      if (!title || !body) {
        return res.status(400).json({
          success: false,
          message:
            'title na body vinahitajika',
        });
      }

      const usersSnapshot =
        await db
          .collection('users')
          .get();

      const tokens = [];

      usersSnapshot.forEach(
        (doc) => {
          const data =
            doc.data();

          if (
            data.fcmToken &&
            typeof data.fcmToken ===
              'string' &&
            data.fcmToken
              .trim() !== ''
          ) {
            tokens.push(
              data.fcmToken.trim(),
            );
          }
        },
      );

      console.log(
        `MATCH ALERT TOKENS FOUND: ${tokens.length}`,
      );

      if (tokens.length === 0) {
        return res.json({
          success: false,
          message:
            'Hakuna FCM tokens zilizopatikana.',
          sent: 0,
        });
      }

      let sent = 0;
      let failed = 0;

      for (
        let i = 0;
        i < tokens.length;
        i += 500
      ) {
        const batch =
          tokens.slice(
            i,
            i + 500,
          );

        const response =
          await getMessaging()
            .sendEachForMulticast({
              tokens:
                batch,

              notification: {
                title:
                  title,

                body:
                  body,
              },

              android: {
                priority:
                  'high',

                notification: {
                  sound:
                    'default',
                },
              },

              apns: {
                payload: {
                  aps: {
                    sound:
                      'default',

                    badge:
                      1,
                  },
                },
              },
            });

        sent +=
          response.successCount;

        failed +=
          response.failureCount;
      }

      console.log(
        `MATCH ALERT RESULT: SENT=${sent}, FAILED=${failed}`,
      );

      res.json({
        success: true,

        message:
          'Match alert imetumwa kwa users wote ✅',

        totalTokens:
          tokens.length,

        sent:
          sent,

        failed:
          failed,
      });

    } catch (error) {
      console.error(
        'MATCH ALERT ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,

        message:
          'Match alert imeshindikana',

        error:
          error.message,
      });
    }
  },
);

// =====================================
// API-FOOTBALL FIXTURES BY DATE
// =====================================

app.get(
  '/api/football/fixtures-date/:date',
  async (req, res) => {
    try {
      const apiKey =
        process.env.FOOTBALL_API_KEY;

      const {
        date,
      } = req.params;

      if (!apiKey) {
        return res.status(500).json({
          success: false,
          message:
            'FOOTBALL_API_KEY haipo kwenye .env',
        });
      }

      if (!date) {
        return res.status(400).json({
          success: false,
          message:
            'Date inahitajika',
        });
      }

      const response =
        await axios.get(
          'https://v3.football.api-sports.io/fixtures',
          {
            params: {
              date:
                date,

              timezone:
                'Africa/Dar_es_Salaam',
            },

            headers: {
              'x-apisports-key':
                apiKey,
            },
          },
        );

      const matches =
        response.data.response || [];

      const fixtures =
        matches.map((match) => ({
          fixtureId:
            match.fixture?.id,

          date:
            match.fixture?.date,

          status:
            match.fixture?.status?.short,

          league:
            match.league?.name,

          homeTeam:
            match.teams?.home?.name,

          awayTeam:
            match.teams?.away?.name,

          homeScore:
            match.goals?.home,

          awayScore:
            match.goals?.away,
        }));

      console.log(
        `FIXTURES FOR ${date}: ${fixtures.length}`,
      );

      res.json({
        success: true,

        date:
          date,

        count:
          fixtures.length,

        fixtures:
          fixtures,
      });

    } catch (error) {
      console.error(
        'FIXTURES BY DATE ERROR:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,

        message:
          'Fixtures za tarehe zimeshindikana',

        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// API-FOOTBALL LIVE MATCHES
// =====================================
// IMPORTANT:
// HII NI READ-ONLY ENDPOINT.
// HAIJITUMII KUTUMA NOTIFICATION.
// =====================================

app.get(
  '/api/football/live',
  async (req, res) => {
    try {
      const apiKey =
        process.env.FOOTBALL_API_KEY;

      if (!apiKey) {
        return res.status(500).json({
          success: false,
          message:
            'FOOTBALL_API_KEY haipo kwenye .env',
        });
      }

      const response =
        await axios.get(
          'https://v3.football.api-sports.io/fixtures',
          {
            params: {
              live:
                'all',
            },

            headers: {
              'x-apisports-key':
                apiKey,
            },
          },
        );

      const matches =
        response.data.response || [];

      console.log(
        `LIVE MATCHES FOUND: ${matches.length}`,
      );

      const liveMatches =
        matches.map((match) => ({
          fixtureId:
            match.fixture?.id,

          status:
            match.fixture?.status?.short,

          elapsed:
            match.fixture?.status?.elapsed,

          league:
            match.league?.name,

          homeTeam:
            match.teams?.home?.name,

          awayTeam:
            match.teams?.away?.name,

          homeScore:
            match.goals?.home,

          awayScore:
            match.goals?.away,
        }));

      res.json({
        success: true,

        count:
          liveMatches.length,

        matches:
          liveMatches,
      });

    } catch (error) {
      console.error(
        'API-FOOTBALL LIVE ERROR:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,

        message:
          'Imeshindikana kupata live matches',

        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// SINGLE FIXTURE LIVE CHECK
// =====================================

app.get(
  '/api/football/fixture/:fixtureId',
  async (req, res) => {
    try {
      const apiKey =
        process.env.FOOTBALL_API_KEY;

      const {
        fixtureId,
      } = req.params;

      if (!apiKey) {
        return res.status(500).json({
          success: false,
          message:
            'FOOTBALL_API_KEY haipo kwenye .env',
        });
      }

      if (!fixtureId) {
        return res.status(400).json({
          success: false,
          message:
            'fixtureId inahitajika',
        });
      }

      const response =
        await axios.get(
          'https://v3.football.api-sports.io/fixtures',
          {
            params: {
              id:
                fixtureId,
            },

            headers: {
              'x-apisports-key':
                apiKey,
            },
          },
        );

      const matches =
        response.data.response || [];

      if (
        matches.length === 0
      ) {
        return res.status(404).json({
          success: false,
          message:
            'Fixture haijapatikana',
        });
      }

      const match =
        matches[0];

      const fixture = {
        fixtureId:
          match.fixture?.id,

        status:
          match.fixture?.status?.short,

        elapsed:
          match.fixture?.status?.elapsed,

        league:
          match.league?.name,

        homeTeam:
          match.teams?.home?.name,

        awayTeam:
          match.teams?.away?.name,

        homeScore:
          match.goals?.home,

        awayScore:
          match.goals?.away,
      };

      console.log(
        'SINGLE FIXTURE:',
        JSON.stringify(
          fixture,
          null,
          2,
        ),
      );

      res.json({
        success: true,
        fixture:
          fixture,
      });

    } catch (error) {
      console.error(
        'SINGLE FIXTURE ERROR:',
        error.response?.data ||
          error.message,
      );

      res.status(
        error.response?.status ||
          500,
      ).json({
        success: false,

        message:
          'Fixture check imeshindikana',

        error:
          error.response?.data ||
          error.message,
      });
    }
  },
);

// =====================================
// SELECTED MATCH MONITOR
// =====================================
// IMPORTANT:
// HII NDIO MONITOR YA GOAL YA APP.
// INAFUATILIA SELECTED MATCH MOJA TU.
// =====================================

async function monitorSelectedMatch() {
  try {
    if (!selectedMatch) {
      console.log(
        'SELECTED MATCH MONITOR: Hakuna match iliyochaguliwa.',
      );
      return;
    }

    const apiKey = process.env.FOOTBALL_API_KEY;

    if (!apiKey) {
      console.log(
        'SELECTED MATCH MONITOR: FOOTBALL_API_KEY haipo.',
      );
      return;
    }

    const fixtureId =
      Number(selectedMatch.fixtureId);

    console.log(
      `🎯 CHECKING SELECTED MATCH: ${selectedMatch.homeTeam} vs ${selectedMatch.awayTeam} | ID=${fixtureId}`,
    );

    const response =
      await axios.get(
        'https://v3.football.api-sports.io/fixtures',
        {
          params: {
            id: fixtureId,
          },

          headers: {
            'x-apisports-key': apiKey,
          },
        },
      );

    const matches =
      response.data.response || [];

    if (matches.length === 0) {
      console.log(
        'SELECTED MATCH MONITOR: Fixture haijapatikana.',
      );
      return;
    }

    const match =
      matches[0];

    const homeTeam =
      match.teams?.home?.name ??
      selectedMatch.homeTeam;

    const awayTeam =
      match.teams?.away?.name ??
      selectedMatch.awayTeam;

    const homeScore =
      Number(match.goals?.home ?? 0);

    const awayScore =
      Number(match.goals?.away ?? 0);

    const status =
      match.fixture?.status?.short ?? '';

    const elapsed =
      Number(
        match.fixture?.status?.elapsed ?? 0,
      );

    const currentState = {
      fixtureId: fixtureId,
      homeScore: homeScore,
      awayScore: awayScore,
      status: status,
    };

    /*
     * ==========================================
     * AUTOMATIC STOP AFTER MATCH FINISHES
     * ==========================================
     */

    const finishedStatuses = [
      'FT',
      'AET',
      'PEN',
      'CANC',
      'PST',
      'ABD',
      'AWD',
      'WO',
    ];

    if (
      finishedStatuses.includes(status)
    ) {
      console.log(
        `🏁 MATCH FINISHED: ${homeTeam} ${homeScore} - ${awayScore} ${awayTeam} | ${status}`,
      );

      selectedMatchState =
        currentState;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .set({
          fixtureId: fixtureId,
          homeScore: homeScore,
          awayScore: awayScore,
          status: status,
          updatedAt:
            FieldValue.serverTimestamp(),
        });

      selectedMatch = null;
      selectedMatchState = null;

      await db
        .collection('settings')
        .doc('selectedMatch')
        .delete();

      console.log(
        '🛑 AUTOMATIC MONITORING STOPPED.',
      );

      console.log(
        'FINAL SCORE SAVED. SELECTED MATCH CLEARED.',
      );

      return;
    }

    console.log(
      `SELECTED MATCH SCORE: ${homeTeam} ${homeScore} - ${awayScore} ${awayTeam} | ${status} | ${elapsed}'`,
    );

    /*
     * ==========================================
     * CHECK STORED STATE
     * ==========================================
     */

    if (
      selectedMatchState &&
      Number(
        selectedMatchState.fixtureId,
      ) !== fixtureId
    ) {
      console.log(
        '⚠️ OLD MATCH STATE RESET.',
      );

      selectedMatchState = null;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .delete();
    }

    /*
     * ==========================================
     * FIRST CHECK
     * ==========================================
     */

    if (!selectedMatchState) {
      selectedMatchState =
        currentState;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .set({
          fixtureId: fixtureId,
          homeScore: homeScore,
          awayScore: awayScore,
          status: status,
          updatedAt:
            FieldValue.serverTimestamp(),
        });

      console.log(
        'SELECTED MATCH INITIAL STATE SAVED TO FIRESTORE.',
      );

      console.log(
        'FIRST CHECK: Notification haitatumwa.',
      );

      return;
    }

    /*
     * ==========================================
     * SCORE COMPARISON
     * ==========================================
     */

    const scoreChanged =
      Number(
        selectedMatchState.homeScore,
      ) !== homeScore ||
      Number(
        selectedMatchState.awayScore,
      ) !== awayScore;

    /*
     * ==========================================
     * NO NEW GOAL
     * ==========================================
     */

    if (!scoreChanged) {
      console.log(
        '✅ HAKUNA GOLI JIPYA.',
      );

      selectedMatchState =
        currentState;

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .set({
          fixtureId: fixtureId,
          homeScore: homeScore,
          awayScore: awayScore,
          status: status,
          updatedAt:
            FieldValue.serverTimestamp(),
        });

      return;
    }

    /*
     * ==========================================
     * SCORE CHANGED
     * ==========================================
     */

    console.log(
      `⚽ GOAL DETECTED: ${homeTeam} ${homeScore} - ${awayScore} ${awayTeam}`,
    );

    /*
     * ==========================================
     * SEND FCM NOTIFICATION
     * ==========================================
     */

    try {
      const usersSnapshot =
        await db
          .collection('users')
          .get();

      const tokens = [];

      usersSnapshot.forEach(
        (doc) => {
          const data =
            doc.data();

          if (
            data.fcmToken &&
            typeof data.fcmToken ===
              'string' &&
            data.fcmToken.trim() !== ''
          ) {
            tokens.push(
              data.fcmToken.trim(),
            );
          }
        },
      );

      const matchAlertsEnabled =
        await areMatchAlertsEnabled();

      if (!matchAlertsEnabled) {
        console.log(
          '🔕 MATCH ALERTS ZIMEZIMWA KUPITIA ADMIN SETTINGS.',
        );

        console.log(
          'ℹ️ Goal imegundulika lakini notification haitatumwa.',
        );
      } else {
        console.log(
          `GOAL ALERT TOKENS FOUND: ${tokens.length}`,
        );

        if (tokens.length > 0) {
          let sent = 0;
          let failed = 0;

          for (
            let i = 0;
            i < tokens.length;
            i += 500
          ) {
            const batch =
              tokens.slice(
                i,
                i + 500,
              );

            const notificationResponse =
              await getMessaging()
                .sendEachForMulticast({
              tokens: batch,

              notification: {
                title:
                  '⚽ GOAL ALERT!',

                body:
                  `${homeTeam} ${homeScore} - ${awayScore} ${awayTeam} | Dakika ${elapsed}'`,
              },

              android: {
                priority: 'high',

                notification: {
                  sound:
                    'default',
                },
              },

              apns: {
                payload: {
                  aps: {
                    sound:
                      'default',

                    badge: 1,
                  },
                },
              },
            });

            sent +=
              notificationResponse.successCount;

            failed +=
              notificationResponse.failureCount;
          }

          console.log(
            `GOAL ALERT RESULT: SENT=${sent}, FAILED=${failed}`,
          );
        } else {
          console.log(
            'GOAL ALERT: Hakuna FCM tokens.',
          );
        }
      }
    } catch (notificationError) {
      console.error(
        'GOAL ALERT NOTIFICATION ERROR:',
        notificationError.message,
      );
    }

    /*
     * ==========================================
     * SAVE NEW STATE
     * ==========================================
     */

    selectedMatchState =
      currentState;

    await db
      .collection('settings')
      .doc('selectedMatchState')
      .set({
        fixtureId: fixtureId,
        homeScore: homeScore,
        awayScore: awayScore,
        status: status,
        updatedAt:
          FieldValue.serverTimestamp(),
      });

    console.log(
      'NEW MATCH STATE SAVED TO FIRESTORE.',
    );

  } catch (error) {
    console.error(
      'SELECTED MATCH MONITOR ERROR:',
      error.response?.data ||
        error.message,
    );
  }
}

/*
 * ==========================================
 * AUTOMATIC SELECTED MATCH MONITOR
 * CHECK EVERY 5 MINUTES
 * ==========================================
 */

let selectedMatchMonitorInterval = null;
let selectedMatchMonitorRunning = false;

function startSelectedMatchMonitoring() {
  if (selectedMatchMonitorInterval) {
    clearInterval(selectedMatchMonitorInterval);
  }
  console.log(
  '⚡ FIRST AUTOMATIC CHECK STARTING...',
);

monitorSelectedMatch();

  selectedMatchMonitorInterval = setInterval(
    async () => {
      if (!selectedMatch) {
        console.log(
          '⏸️ AUTO MONITOR: Hakuna selected match.',
        );
        return;
      }

      if (selectedMatchMonitorRunning) {
        console.log(
          '⏳ AUTO MONITOR: Check ya nyuma bado inaendelea.',
        );
        return;
      }

      selectedMatchMonitorRunning = true;

      try {
        console.log(
          '⏱️ AUTO MONITOR: Checking selected match...',
        );

        await monitorSelectedMatch();
      } catch (error) {
        console.error(
          'AUTO MONITOR ERROR:',
          error.message,
        );
      } finally {
        selectedMatchMonitorRunning = false;
      }
    },
    5 * 60 * 1000,
  );

  console.log(
    '▶️ AUTOMATIC SELECTED MATCH MONITOR STARTED.',
  );
}

function stopSelectedMatchMonitoring() {
  if (selectedMatchMonitorInterval) {
    clearInterval(
      selectedMatchMonitorInterval,
    );

    selectedMatchMonitorInterval = null;
  }

  console.log(
    '🛑 AUTOMATIC SELECTED MATCH MONITOR STOPPED.',
  );
}
// =====================================
// MANUAL SELECTED MATCH MONITOR
// =====================================

app.post(
  '/api/football/select-match',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        fixtureId,
        homeTeam,
        awayTeam,
      } = req.body;

      if (!fixtureId) {
        return res.json({
          success: false,

          message:
            'Hakuna match iliyochaguliwa.',
        });
      }

      console.log(
        `🎯 MANUAL CHECK: ${selectedMatch.homeTeam} vs ${selectedMatch.awayTeam}`,
      );

      await monitorSelectedMatch();

      res.json({
        success: true,

        message:
          'Selected match monitor ime-run kikamilifu.',

        match:
          selectedMatch,

        state:
          selectedMatchState,
      });

    } catch (error) {
      console.error(
        'MANUAL SELECTED MATCH MONITOR ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,

        message:
          'Selected match monitor imeshindikana.',

        error:
          error.message,
      });
    }
  },
);

// =====================================
// CLEAR SELECTED MATCH
// =====================================

app.post(
  '/api/football/clear-selected-match',
  async (req, res) => {
    try {

      // =====================================
      // STOP AUTOMATIC MONITORING
      // =====================================

      stopSelectedMatchMonitoring();

      // =====================================
      // CLEAR MEMORY
      // =====================================

      selectedMatch = null;
      selectedMatchState = null;

      // =====================================
      // CLEAR FIRESTORE SELECTED MATCH
      // =====================================

      await db
        .collection('settings')
        .doc('selectedMatch')
        .delete();

      // =====================================
      // CLEAR FIRESTORE MATCH STATE
      // =====================================

      await db
        .collection('settings')
        .doc('selectedMatchState')
        .delete();

      console.log(
        '🛑 SELECTED MATCH MONITORING STOPPED.',
      );

      console.log(
        'SELECTED MATCH AND STATE CLEARED FROM FIRESTORE.',
      );

      // =====================================
      // RESPONSE
      // =====================================

      res.json({
        success: true,
        message:
          'Monitoring imesimamishwa kikamilifu ✅',
      });

    } catch (error) {

      console.error(
        'STOP MONITORING ERROR:',
        error.message,
      );

      res.status(500).json({
        success: false,
        message:
          'Kusimamisha monitoring kumeshindikana.',
        error: error.message,
      });
    }
  },
);

app.get('/api/football/find-arsenal-chelsea', async (req, res) => {
  try {
    const apiKey = process.env.FOOTBALL_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: 'FOOTBALL_API_KEY haipo.',
      });
    }

    const response = await axios.get(
      'https://v3.football.api-sports.io/fixtures',
      {
        params: {
          league: 39,
          season: 2026,
          team: 42,
        },
        headers: {
          'x-apisports-key': apiKey,
        },
      },
    );

    const matches = response.data.response || [];

    const filtered = matches.filter((match) => {
      const home =
          match.teams?.home?.name
              ?.toLowerCase() ?? '';

      const away =
          match.teams?.away?.name
              ?.toLowerCase() ?? '';

      return (
        (home.includes('arsenal') &&
            away.includes('chelsea')) ||
        (home.includes('chelsea') &&
            away.includes('arsenal'))
      );
    });

    console.log(
      'ARSENAL CHELSEA RESULT:',
      JSON.stringify(filtered, null, 2),
    );

    res.json({
      success: true,
      count: filtered.length,
      matches: filtered.map((match) => ({
        fixtureId: match.fixture?.id,
        date: match.fixture?.date,
        status: match.fixture?.status,
        league: match.league,
        homeTeam: match.teams?.home?.name,
        awayTeam: match.teams?.away?.name,
        score: match.goals,
      })),
    });

  } catch (error) {
    console.error(
      'ARSENAL CHELSEA ERROR:',
      error.response?.data || error.message,
    );

    res.status(500).json({
      success: false,
      error:
          error.response?.data ||
          error.message,
    });
  }
});

// =========================================================
// FIND FOOTBALL MATCH
// =========================================================
app.get('/api/football/find-match', async (req, res) => {
  try {
    const { home, away, date } = req.query;

    if (!home || !away || !date) {
      return res.status(400).json({
        success: false,
        message: 'home, away na date vinahitajika.',
      });
    }

    const apiKey = process.env.FOOTBALL_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: 'FOOTBALL_API_KEY haipo.',
      });
    }

    console.log(
      `🔎 FIND MATCH: ${home} vs ${away} | ${date}`,
    );

    const response = await axios.get(
      'https://v3.football.api-sports.io/fixtures',
      {
        params: {
          league: 39,
          season: 2026,
          date: date,
          timezone: 'Africa/Dar_es_Salaam',
        },
        headers: {
          'x-apisports-key': apiKey,
        },
      },
    );

    const matches =
        response.data.response || [];

    console.log(
      `FIXTURES RETURNED: ${matches.length}`,
    );

    const homeSearch =
        home.toLowerCase().trim();

    const awaySearch =
        away.toLowerCase().trim();

    const filtered =
        matches.filter((match) => {
      const homeName =
          match.teams?.home?.name
              ?.toLowerCase() ?? '';

      const awayName =
          match.teams?.away?.name
              ?.toLowerCase() ?? '';

      return (
        homeName.includes(homeSearch) &&
        awayName.includes(awaySearch)
      );
    });

    console.log(
      `MATCHES FOUND: ${filtered.length}`,
    );

    res.json({
      success: true,
      count: filtered.length,

      matches: filtered.map((match) => ({
        fixtureId:
            match.fixture?.id,

        date:
            match.fixture?.date,

        status:
            match.fixture?.status?.short ?? '',

        league:
            match.league?.name ?? '',

        round:
            match.league?.round ?? '',

        homeTeam:
            match.teams?.home?.name ?? '',

        awayTeam:
            match.teams?.away?.name ?? '',

        homeScore:
            match.goals?.home,

        awayScore:
            match.goals?.away,
      })),
    });

  } catch (error) {
    console.error(
      'FIND MATCH ERROR:',
      error.response?.data ||
          error.message,
    );

    res.status(500).json({
      success: false,
      error:
          error.response?.data ||
          error.message,
    });
  }
});

app.get('/api/football/live', async (req, res) => {
  try {
    const apiKey = process.env.FOOTBALL_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: 'FOOTBALL_API_KEY haipo.',
      });
    }

    console.log('🔴 GET LIVE FIXTURES...');

    const response = await axios.get(
      'https://v3.football.api-sports.io/fixtures',
      {
        params: {
          live: 'all',
        },
        headers: {
          'x-apisports-key': apiKey,
        },
      },
    );

    const matches =
        response.data.response || [];

    console.log(
      `LIVE FIXTURES RETURNED: ${matches.length}`,
    );

    res.json({
      success: true,
      count: matches.length,
      matches: matches.map((match) => ({
        fixtureId: match.fixture?.id,

        date: match.fixture?.date,

        status:
            match.fixture?.status?.short ?? '',

        elapsed:
            match.fixture?.status?.elapsed ?? 0,

        league:
            match.league?.name ?? '',

        homeTeam:
            match.teams?.home?.name ?? '',

        awayTeam:
            match.teams?.away?.name ?? '',

        homeScore:
            match.goals?.home ?? 0,

        awayScore:
            match.goals?.away ?? 0,
      })),
    });

  } catch (error) {
    console.error(
      'LIVE FIXTURES ERROR:',
      error.response?.data ||
          error.message,
    );

    res.status(500).json({
      success: false,
      error:
          error.response?.data ||
          error.message,
    });
  }
});

// ===============================
// 🤖 OPENAI AI TEST
// ===============================

const OpenAI = require('openai');

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

app.get('/api/ai/test', async (req, res) => {
  try {
    const response = await openai.responses.create({
      model: 'gpt-5.6-luna',
      input: 'Jibu kwa kifupi kwa Kiswahili: AI ya Jamvi Kuu Tips iko tayari.',
    });

    res.json({
      success: true,
      message: response.output_text,
    });

  } catch (error) {
    console.error('OPENAI TEST ERROR:', error);

    res.status(500).json({
      success: false,
      message: 'OpenAI test imeshindikana.',
      error: error.message,
    });
  }
});

// ===============================
// 🤖 REAL AI FOOTBALL ANALYSIS
// VERSION 2
// FORM + H2H + TEAM STATS
// ===============================

app.post('/api/ai/analyze-match', async (req, res) => {
  try {
    const { fixtureId } = req.body;

    if (!fixtureId) {
      return res.status(400).json({
        success: false,
        message: 'fixtureId inahitajika.',
      });
    }

    console.log('======================================');
    console.log('🤖 REAL AI ANALYSIS V2');
    console.log('Fixture ID:', fixtureId);
    console.log('======================================');

    const apiHeaders = {
      'x-apisports-key': process.env.FOOTBALL_API_KEY,
    };

    // ======================================
    // 1. GET MAIN FIXTURE
    // ======================================

    const fixtureResponse = await axios.get(
      'https://v3.football.api-sports.io/fixtures',
      {
        params: {
          id: fixtureId,
        },
        headers: apiHeaders,
      }
    );

    const fixtures = fixtureResponse.data.response;

    if (!fixtures || fixtures.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Mechi haijapatikana API-Football.',
      });
    }

    const fixture = fixtures[0];

    const homeTeamId = fixture.teams.home.id;
    const awayTeamId = fixture.teams.away.id;

    const leagueId = fixture.league.id;
    const season = fixture.league.season;

    const matchData = {
      fixtureId: fixture.fixture.id,
      date: fixture.fixture.date,
      status: fixture.fixture.status.short,

      league: fixture.league.name,
      leagueId: leagueId,
      season: season,
      country: fixture.league.country,

      homeTeam: fixture.teams.home.name,
      awayTeam: fixture.teams.away.name,

      homeTeamId: homeTeamId,
      awayTeamId: awayTeamId,

      homeGoals: fixture.goals.home,
      awayGoals: fixture.goals.away,
    };

    console.log('⚽ MATCH:', matchData);

    // ======================================
    // 2. GET RECENT FORM - HOME TEAM
    // ======================================

    const homeFormResponse = await axios.get(
      'https://v3.football.api-sports.io/fixtures',
      {
        params: {
  team: homeTeamId,
  last: 5,
  status: 'FT',
},
        headers: apiHeaders,
      }
    );

    // ======================================
    // 3. GET RECENT FORM - AWAY TEAM
    // ======================================

    const awayFormResponse = await axios.get(
  'https://v3.football.api-sports.io/fixtures',
  {
    params: {
      team: awayTeamId,
      last: 5,
      status: 'FT',
    },
    headers: apiHeaders,
  }
);

    console.log('================ RECENT FORM DEBUG ================');

console.log(
  '🏠 HOME FORM RAW COUNT:',
  homeFormResponse.data.response?.length || 0
);

console.log(
  '✈️ AWAY FORM RAW COUNT:',
  awayFormResponse.data.response?.length || 0
);

console.log(
  '🏠 HOME FORM SAMPLE:',
  JSON.stringify(
    homeFormResponse.data.response?.[0] || null,
    null,
    2
  )
);

console.log(
  '✈️ AWAY FORM SAMPLE:',
  JSON.stringify(
    awayFormResponse.data.response?.[0] || null,
    null,
    2
  )
);

    // ======================================
    // 4. FORMAT RECENT FORM
    // ======================================

    function formatRecentMatches(response, teamId) {
      const matches = response.data.response || [];

      return matches.map((item) => {
        const isHome = item.teams.home.id === teamId;

        const scored = isHome
          ? item.goals.home
          : item.goals.away;

        const conceded = isHome
          ? item.goals.away
          : item.goals.home;

        let result = 'DRAW';

        if (scored > conceded) {
          result = 'WIN';
        } else if (scored < conceded) {
          result = 'LOSS';
        }

        return {
          date: item.fixture.date,

          opponent: isHome
            ? item.teams.away.name
            : item.teams.home.name,

          homeTeam: item.teams.home.name,
          awayTeam: item.teams.away.name,

          scored: scored,
          conceded: conceded,

          result: result,
        };
      });
    }

    const homeRecentForm = formatRecentMatches(
      homeFormResponse,
      homeTeamId
    );

    const awayRecentForm = formatRecentMatches(
      awayFormResponse,
      awayTeamId
    );

    console.log('================ FORM FORMAT DEBUG ================');

console.log(
  'HOME RECENT FORM COUNT:',
  homeRecentForm.length
);

console.log(
  'AWAY RECENT FORM COUNT:',
  awayRecentForm.length
);

console.log(
  'HOME RECENT FORM:',
  JSON.stringify(homeRecentForm, null, 2)
);

console.log(
  'AWAY RECENT FORM:',
  JSON.stringify(awayRecentForm, null, 2)
);

console.log('====================================================');
    // ======================================
    // 5. GET H2H
    // ======================================

    const h2hResponse = await axios.get(
      'https://v3.football.api-sports.io/fixtures/headtohead',
      {
        params: {
          h2h: `${homeTeamId}-${awayTeamId}`,
          last: 5,
        },
        headers: apiHeaders,
      }
    );

    const h2hMatches = (h2hResponse.data.response || []).map(
      (item) => ({
        date: item.fixture.date,

        homeTeam: item.teams.home.name,
        awayTeam: item.teams.away.name,

        homeGoals: item.goals.home,
        awayGoals: item.goals.away,
      })
    );

    // ======================================
    // 6. GET HOME TEAM SEASON STATISTICS
    // ======================================

    let homeStats = null;

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/teams/statistics',
        {
          params: {
            league: leagueId,
            season: season,
            team: homeTeamId,
          },
          headers: apiHeaders,
        }
      );

      homeStats = response.data.response || null;
    } catch (error) {
      console.log(
        '⚠️ HOME TEAM STATS FAILED:',
        error.response?.data || error.message
      );
    }

    // ======================================
    // 7. GET AWAY TEAM SEASON STATISTICS
    // ======================================

    let awayStats = null;

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/teams/statistics',
        {
          params: {
            league: leagueId,
            season: season,
            team: awayTeamId,
          },
          headers: apiHeaders,
        }
      );

      awayStats = response.data.response || null;
    } catch (error) {
      console.log(
        '⚠️ AWAY TEAM STATS FAILED:',
        error.response?.data || error.message
      );
    }

    // ======================================
    // 8. GET API-FOOTBALL PREDICTION
    // ======================================

    let apiPrediction = null;

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/predictions',
        {
          params: {
            fixture: fixtureId,
          },
          headers: apiHeaders,
        }
      );

      apiPrediction =
        response.data.response?.[0] || null;
    } catch (error) {
      console.log(
        '⚠️ API PREDICTION FAILED:',
        error.response?.data || error.message
      );
    }

        // ======================================
    // 9. GET LIVE MATCH STATISTICS
    // ======================================

    let liveStatistics = [];

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/fixtures/statistics',
        {
          params: {
            fixture: fixtureId,
          },
          headers: apiHeaders,
        }
      );

      liveStatistics =
        response.data.response || [];

      console.log(
        '📊 LIVE STATISTICS:',
        liveStatistics.length
      );

    } catch (error) {
      console.log(
        '⚠️ LIVE STATISTICS FAILED:',
        error.response?.data || error.message
      );
    }

        // ======================================
    // 📊 FORMAT LIVE STATISTICS
    // ======================================

    function formatLiveStatistics(statistics) {
      return (statistics || []).map((teamData) => {
        const values = {};

        for (const item of teamData.statistics || []) {
          values[item.type] = item.value;
        }

        return {
          teamId: teamData.team?.id || null,
          team: teamData.team?.name || 'Unknown',

          possession: values['Ball Possession'] ?? null,
          totalShots: values['Total Shots'] ?? null,
          shotsOnGoal: values['Shots on Goal'] ?? null,
          shotsOffGoal: values['Shots off Goal'] ?? null,
          shotsInsideBox: values['Shots insidebox'] ?? null,
          shotsOutsideBox: values['Shots outsidebox'] ?? null,
          blockedShots: values['Blocked Shots'] ?? null,
          corners: values['Corner Kicks'] ?? null,
          offsides: values['Offsides'] ?? null,
          fouls: values['Fouls'] ?? null,
          yellowCards: values['Yellow Cards'] ?? null,
          redCards: values['Red Cards'] ?? null,
          totalPasses: values['Total passes'] ?? null,
          accuratePasses: values['Passes accurate'] ?? null,
          goalkeeperSaves: values['Goalkeeper Saves'] ?? null,
        };
      });
    }

    const liveStatisticsFormatted =
      formatLiveStatistics(liveStatistics);

          // ======================================
    // 👕 GET MATCH LINEUPS
    // ======================================

    let lineups = [];

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/fixtures/lineups',
        {
          params: {
            fixture: fixtureId,
          },
          headers: apiHeaders,
        }
      );

      lineups = response.data.response || [];

      console.log(
        '👕 LINEUPS:',
        lineups.length
      );

    } catch (error) {
      console.log(
        '⚠️ LINEUPS FAILED:',
        error.response?.data || error.message
      );
    }

        // ======================================
    // 👕 FORMAT LINEUPS
    // ======================================

    function formatLineups(lineupsData) {
      return (lineupsData || []).map((teamData) => {
        return {
          teamId: teamData.team?.id || null,

          team: teamData.team?.name || 'Unknown',

          formation: teamData.formation || null,

          coach: teamData.coach?.name || null,

          startingXI: (teamData.startXI || []).map((player) => ({
            id: player.player?.id || null,
            name: player.player?.name || null,
            number: player.player?.number || null,
            position: player.player?.pos || null,
            grid: player.player?.grid || null,
          })),

          substitutes: (teamData.substitutes || []).map((player) => ({
            id: player.player?.id || null,
            name: player.player?.name || null,
            number: player.player?.number || null,
            position: player.player?.pos || null,
          })),
        };
      });
    }

    const lineupsFormatted =
      formatLineups(lineups);

          // ======================================
    // 🏥 GET MATCH INJURIES
    // ======================================

    let injuries = [];

    try {
      const response = await axios.get(
        'https://v3.football.api-sports.io/injuries',
        {
          params: {
            fixture: fixtureId,
          },
          headers: apiHeaders,
        }
      );

      injuries = response.data.response || [];

      console.log(
        '🏥 INJURIES:',
        injuries.length
      );

    } catch (error) {
      console.log(
        '⚠️ INJURIES FAILED:',
        error.response?.data || error.message
      );
    }
        // ======================================
    // 🏥 FORMAT INJURIES
    // ======================================

    function formatInjuries(injuriesData) {
      return (injuriesData || []).map((item) => {
        return {
          teamId: item.team?.id || null,

          team: item.team?.name || 'Unknown',

          playerId: item.player?.id || null,

          player: item.player?.name || 'Unknown',

          type: item.type || null,

          reason: item.reason || null,
        };
      });
    }

    const injuriesFormatted =
      formatInjuries(injuries);

      // ======================================
// ⚽ GET MATCH EVENTS
// ======================================

let matchEvents = [];

try {
  const response = await axios.get(
    'https://v3.football.api-sports.io/fixtures/events',
    {
      params: {
        fixture: fixtureId,
      },
      headers: apiHeaders,
    }
  );

  matchEvents = response.data.response || [];

  console.log(
    '⚽ MATCH EVENTS:',
    matchEvents.length
  );

} catch (error) {
  console.log(
    '⚠️ MATCH EVENTS FAILED:',
    error.response?.data || error.message
  );
}
// ======================================
// ⚽ FORMAT MATCH EVENTS
// ======================================

function formatMatchEvents(eventsData) {
  return (eventsData || []).map((event) => {
    return {
      time: event.time
        ? {
            elapsed: event.time.elapsed || null,
            extra: event.time.extra || null,
          }
        : null,

      teamId: event.team?.id || null,
      team: event.team?.name || 'Unknown',

      playerId: event.player?.id || null,
      player: event.player?.name || null,

      assistId: event.assist?.id || null,
      assist: event.assist?.name || null,

      type: event.type || null,
      detail: event.detail || null,

      comments: event.comments || null,
    };
  });
}

const matchEventsFormatted =
  formatMatchEvents(matchEvents);

// ======================================
// 📊 COMPACT FOOTBALL DATA FOR AI
// ======================================

// ======================================
// 📊 COMPACT FOOTBALL DATA FOR AI
// ======================================

function compactSeasonStats(stats) {
  if (!stats) {
    return null;
  }

  return {
    team: stats.team
      ? {
          id: stats.team.id || null,
          name: stats.team.name || null,
        }
      : null,

    league: stats.league
      ? {
          id: stats.league.id || null,
          name: stats.league.name || null,
          country: stats.league.country || null,
          season: stats.league.season || null,
        }
      : null,

    fixtures: stats.fixtures
      ? {
          played: stats.fixtures.played || null,
          wins: stats.fixtures.wins || null,
          draws: stats.fixtures.draws || null,
          loses: stats.fixtures.loses || null,
        }
      : null,

    goals: stats.goals
      ? {
          for: stats.goals.for || null,
          against: stats.goals.against || null,
        }
      : null,

    cleanSheet: stats.clean_sheet || null,

    failedToScore: stats.failed_to_score || null,

    biggest: stats.biggest
      ? {
          wins: stats.biggest.wins || null,
          loses: stats.biggest.loses || null,
          goals: stats.biggest.goals || null,
        }
      : null,
  };
}

function compactApiPrediction(prediction) {
  if (!prediction) {
    return null;
  }

  return {
    predictions: prediction.predictions
      ? {
          winner:
            prediction.predictions.winner || null,

          win_or_draw:
            prediction.predictions.win_or_draw ?? null,

          under_over:
            prediction.predictions.under_over || null,

          goals:
            prediction.predictions.goals || null,

          advice:
            prediction.predictions.advice || null,

          percent:
            prediction.predictions.percent || null,
        }
      : null,

    teams: prediction.teams
      ? {
          home: prediction.teams.home
            ? {
                id:
                  prediction.teams.home.id ||
                  null,

                name:
                  prediction.teams.home.name ||
                  null,

                last_5:
                  prediction.teams.home.last_5 ||
                  null,

                form:
                  prediction.teams.home.form ||
                  null,
              }
            : null,

          away: prediction.teams.away
            ? {
                id:
                  prediction.teams.away.id ||
                  null,

                name:
                  prediction.teams.away.name ||
                  null,

                last_5:
                  prediction.teams.away.last_5 ||
                  null,

                form:
                  prediction.teams.away.form ||
                  null,
              }
            : null,
        }
      : null,
  };
}

const footballData = {
  match: matchData,

  recentForm: {
    home: homeRecentForm || [],
    away: awayRecentForm || [],
  },

  headToHead: h2hMatches || [],

  seasonStatistics: {
    home: compactSeasonStats(homeStats),
    away: compactSeasonStats(awayStats),
  },

  apiFootballPrediction:
    compactApiPrediction(apiPrediction),

  liveStatistics:
    (liveStatisticsFormatted || []).map((item) => ({
      teamId: item.teamId || null,
      team: item.team || null,
      possession: item.possession ?? null,
      totalShots: item.totalShots ?? null,
      shotsOnGoal: item.shotsOnGoal ?? null,
      shotsOffGoal: item.shotsOffGoal ?? null,
      corners: item.corners ?? null,
      fouls: item.fouls ?? null,
      yellowCards: item.yellowCards ?? null,
      redCards: item.redCards ?? null,
    })),

  injuries:
    (injuriesFormatted || []).map((item) => ({
      teamId: item.teamId || null,
      team: item.team || null,
      player: item.player || null,
      type: item.type || null,
      reason: item.reason || null,
    })),

  events:
    (matchEventsFormatted || []).map((item) => ({
      time: item.time || null,
      teamId: item.teamId || null,
      team: item.team || null,
      player: item.player || null,
      type: item.type || null,
      detail: item.detail || null,
    })),
};

console.log('📊 COMPACT AI DATA READY');

console.log(
  'Recent Home:',
  footballData.recentForm.home.length
);

console.log(
  'Recent Away:',
  footballData.recentForm.away.length
);

console.log(
  'H2H:',
  footballData.headToHead.length
);

console.log(
  'Home Season Stats:',
  footballData.seasonStatistics.home
    ? 'YES'
    : 'NO'
);

console.log(
  'Away Season Stats:',
  footballData.seasonStatistics.away
    ? 'YES'
    : 'NO'
);

console.log(
  'API Prediction:',
  footballData.apiFootballPrediction
    ? 'YES'
    : 'NO'
);

    console.log('📊 FOOTBALL DATA COLLECTED');
    console.log(
      'Home form:',
      homeRecentForm.length
    );
    console.log(
      'Away form:',
      awayRecentForm.length
    );
    console.log(
      'H2H:',
      h2hMatches.length
    );
    console.log(
      'API prediction:',
      apiPrediction ? 'YES' : 'NO'
    );

    // ======================================
    // 10. SEND DATA TO OPENAI
    // ======================================

console.log('================ FORM CHECK ================');

console.log(
  'HOME FORM COUNT:',
  homeRecentForm.length
);

console.log(
  'AWAY FORM COUNT:',
  awayRecentForm.length
);

console.log(
  'HOME FORM:',
  JSON.stringify(homeRecentForm, null, 2)
);

console.log(
  'AWAY FORM:',
  JSON.stringify(awayRecentForm, null, 2)
);

console.log('============================================');

// ======================================
// 🤖 COMPACT AI PROMPT
// ======================================

const prompt = `
Wewe ni AI Football Analysis Engine wa Jamvi Kuu Tips.

Tumia FOOTBALL DATA iliyopo hapa chini pekee.

SHERIA:

1. Usibuni statistics.
2. Usitumie knowledge ya nje ya FOOTBALL DATA.
3. Usitumie odds.
4. Usidai prediction ni guaranteed au 100%.
5. Data ikiwa haipo, tumia "NO DATA".
6. Recent form ikiwa tupu, sema "Hakuna recent form data iliyopatikana."
7. H2H ikiwa tupu, sema "Hakuna H2H data iliyopatikana."
8. Season statistics ikiwa haipo, sema "Season statistics hazijapatikana."
9. API-Football prediction ikiwa haipo, sema "API prediction haijapatikana."
10. Confidence iwe kati ya 0 na 100.
11. Confidence ipungue kama data ni chache, tupu au zinakinzana.
12. Reasons zote lazima zitokane na data iliyotolewa.
13. Kwa FT, usiwasilishe matokeo ya mwisho kama prediction ya kabla ya mechi.
14. Kwa LIVE, tumia score na live statistics zilizopo.
15. Kwa PRE-MATCH, tumia available pre-match data.
16. Usitengeneze prediction kama data haitoshi.
17. Bora kusema NO DATA kuliko kubuni.

FOOTBALL DATA:

${JSON.stringify(footballData)}

Rudisha JSON ONLY kwa format hii:

{
  "match": {
    "homeTeam": "",
    "awayTeam": "",
    "league": ""
  },

  "prediction": {
    "result": "HOME | DRAW | AWAY | NO DATA",
    "doubleChance": "1X | X2 | 12 | NO DATA",
    "overUnder": "OVER 2.5 | UNDER 2.5 | NO DATA",
    "btts": "YES | NO | NO DATA",
    "correctScore": "NO DATA"
  },

  "confidence": 0,

  "risk": "LOW | MEDIUM | HIGH",

  "analysis": "",

  "reasons": [
    "",
    "",
    ""
  ],

  "formSummary": {
    "home": "",
    "away": ""
  },

  "h2hSummary": "",

  "dataQuality": ""
}
`;

    const aiResponse = await openai.responses.create({
  model: 'gpt-5.6-luna',
  input: prompt,
  max_output_tokens: 2500,
});

    const aiText = aiResponse.output_text;

    console.log('🤖 AI RESPONSE RECEIVED');

    // ======================================
    // 11. PARSE AI JSON
    // ======================================

    let analysis;

    try {
      analysis = JSON.parse(aiText);
    } catch (error) {
      console.log(
        '⚠️ AI JSON PARSE FAILED'
      );

      analysis = {
        rawAnalysis: aiText,
      };
    }

    // ======================================
    // 12. SAVE TO FIRESTORE
    // ======================================

    await db
      .collection('ai_analyses')
      .doc(String(fixtureId))
      .set(
        {
          fixtureId: Number(fixtureId),

          matchData: matchData,

          footballData: footballData,

          analysis: analysis,

          generatedAt:
            FieldValue.serverTimestamp(),
        },
        {
          merge: true,
        }
      );

    console.log(
      '✅ AI ANALYSIS V2 SAVED TO FIRESTORE'
    );

    // ======================================
    // 13. RETURN RESULT
    // ======================================

    res.json({
      success: true,

      fixtureId: Number(fixtureId),

      match: matchData,

   dataUsed: {
  recentForm: {
    home: homeRecentForm.length,
    away: awayRecentForm.length,
  },

  h2h: h2hMatches.length,

  liveStatistics: {
    available: liveStatistics.length > 0,
    teams: liveStatistics.length,
  },

  lineups: {
    available: lineupsFormatted.length > 0,
    teams: lineupsFormatted.length,
  },

  injuries: {
    available: injuriesFormatted.length > 0,
    total: injuriesFormatted.length,
  },

  events: {
    available: matchEventsFormatted.length > 0,
    total: matchEventsFormatted.length,
  },

  homeSeasonStats: !!homeStats,

  awaySeasonStats: !!awayStats,

  apiFootballPrediction: !!apiPrediction,
},
      analysis: analysis,
    });

  } catch (error) {
    console.error(
      '❌ AI ANALYSIS V2 ERROR:',
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,

      message:
        'Real AI Football Analysis imeshindikana.',

      error:
        error.response?.data ||
        error.message,
    });
  }
});

// =====================================
// START SERVER
// =====================================

const server = app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Server imeanza kwenye port ${PORT}`);

  await loadSelectedMatch();
  await loadSelectedMatchState();

  if (selectedMatch) {
    console.log('🔄 SELECTED MATCH FOUND AFTER SERVER START.');
    startSelectedMatchMonitoring();
    console.log('▶️ AUTOMATIC MONITORING RESTORED.');
  } else {
    console.log('⏸️ NO SELECTED MATCH. MONITORING NOT STARTED.');
  }
});

server.on('error', (error) => {
  console.error('SERVER ERROR:', error);
});

server.on('close', () => {
  console.log('SERVER CLOSED');
});

process.stdin.resume();

// ===============================
// ⚽ LIVE STATISTICS TEST
// ===============================

app.get('/api/football/live-stats/:fixtureId', async (req, res) => {
  try {
    const fixtureId = req.params.fixtureId;

    const response = await axios.get(
      'https://v3.football.api-sports.io/fixtures/statistics',
      {
        params: {
          fixture: fixtureId,
        },
        headers: {
          'x-apisports-key': process.env.FOOTBALL_API_KEY,
        },
      }
    );

    const statistics = response.data?.response || [];

    if (!statistics.length) {
      return res.json({
        success: true,
        fixtureId: Number(fixtureId),
        statistics: [],
        message: 'Hakuna live statistics zilizopatikana kwa mechi hii.',
      });
    }

    res.json({
      success: true,
      fixtureId: Number(fixtureId),
      statistics,
    });

  } catch (error) {
    console.error(
      'LIVE STATISTICS ERROR:',
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,
      message: 'Imeshindikana kupata live statistics.',
      error: error.response?.data || error.message,
    });
  }
});

server.on(
  'error',
  (error) => {
    console.error(
      'SERVER ERROR:',
      error,
    );
  },
);

server.on(
  'close',
  () => {
    console.log(
      'SERVER IMEFUNGWA',
    );
  },
);

process.stdin.resume();