const express = require('express')
const app = express()
const port = 3000;
const path = require('path')
var http = require('http');
const https = require('https');

// Log time for rendering each request
app.use((req, res, next) => {
    let startTimeForPage = Date.now();
    // logger.debug(req.method, req.originalUrl, '[START]');
    res.on('finish', () => {   
      let pageRenderTime = Date.now() - startTimeForPage;
    //   utils.count("pageRenderTime", pageRenderTime);         
      var sessionId = req.sessionID ? req.sessionID : 'unknown-session-id';
    //   logger.info(req.method, req.originalUrl, sessionId, '[FINISH] renderTime: ' + pageRenderTime);
    });
    res.on('close', () => {
      console.log(req.method, req.originalUrl, '[CLOSED-BY-CLIENT]');
    });
    // Count requests processed
    if(req.originalUrl.indexOf('/api') === -1) {
    //   utils.count("pageRequestCount", 1);
    } else {
    //   utils.count("apiRequestCount", 1);
    }
    next();
  });

  // Security conscious headers
  app.disable('x-powered-by');
//   app.use(expectCt({ enforce: true, maxAge: 36000000 }));
  app.use(function (req, res, next) {
    // Ignore dev testing on localhost
    // if(config.env !== 'development') {
    //   res.setHeader('Strict-Transport-Security', 'max-age=36000000; includeSubDomains');
    // }
    console.log("req.headers.host", req.headers.host)
    return next();
  });

  app.get('/api/healthquick', (req, res) => {
    res.send('ok')
  })
  
  app.set('view engine', 'html');
  // Serve without implementing session for static files
  let publicDirectory = path.join(__dirname, 'public');
//   app.use('/static', express.static(publicDirectory));
//   app.use('/public', express.static(publicDirectory));

  // Sessions Config
//   app.use(cookieParser());
//   var domainName = config.serverHost.replace('http://', '').replace('https://','');
//   var sessionConfig = {
//     secret: 'davraSessionSecret',
//     saveUninitialized: false,
//     resave: false,
//     store: sessionStore,
//     name: 'sessionId',
//     cookie: { 
//       secure: true,
//       sameSite: 'lax',
//       httpOnly: true,
//       domain: domainName,
//       maxAge: 36000000 
//     }
//   };
//   if(config.env === 'development') {
//     delete(sessionConfig.cookie.secure);
//     delete(sessionConfig.cookie.httpOnly);
//     delete(sessionConfig.cookie.domain);
//   }
//   app.use(session(sessionConfig));

  // Ensure HTTPS is in use. If HTTP then redirect to https version
  app.enable('trust proxy');
  app.use((req, res, next) => {
    // if (config.env === 'development' || req.secure === true) {
    //   return next();
    // } else {
    //   logger.info('Redirecting from http to https://' + req.headers.host + req.url);
    //   return res.redirect(config.serverHost + req.url);
    // }
    next();
  });

  // Security conscious headers
  app.use(function (req, res, next) {
    // const allowedOrigins = [config.serverHost + ':' + config.serverPort];
    // const origin = req.headers.origin;
    // if (allowedOrigins.indexOf(origin) > -1) {
    //   res.setHeader('Access-Control-Allow-Origin', origin);
    // }
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS, PUT, POST');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Referrer-Policy', 'origin');
    res.header('Cache-Control', 'no-cache');
    res.header('Pragma', 'no-cache');
    // if(config.env !== 'development') {
    //   res.header('Content-Security-Policy', "default-src https: wss:; img-src https: 'unsafe-inline' data:; script-src https: 'unsafe-inline'; style-src https: 'unsafe-inline'; media-src https: data: 'unsafe-inline';");
    // } else {
    //   res.header('Content-Security-Policy', "default-src http: https: ws: wss:; img-src http: 'unsafe-inline' data:; script-src http: 'unsafe-inline'; style-src http: 'unsafe-inline'; media-src https: data: 'unsafe-inline';");
    // }
    next();
  });

//   app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Hello World!')
})
const config = {
    serverPort: "3000"
}
/**
 * Create HTTP server.
 */
 var httpServer = http.createServer(app);
 // Listen on provided port
 httpServer.listen(config.serverPort);
 httpServer.on('error', function(err) {
   console.log('HTTP Server Error', err);
//    onError(err);
 });
 httpServer.on('listening', function() {
    console.log('HTTP server listening on port', config.serverPort);
 });
 