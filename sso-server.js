//sso server:


// List of allowed root domains
const allowedRootDomains = [
  "site1.com",
  "site2.com",
  "site3.com"
  // Add more trusted domains here
];

// Function to extract the root domain from an Origin header
function getRootDomain(origin) {
  try {
    const url = new URL(origin);
    const parts = url.hostname.split(".");
    if (parts.length >= 2) {
      return parts.slice(-2).join("."); // Extracts "site1.com" from "sub.site1.com"
    }
  } catch (error) {
    return null;
  }
  return null;
}

// Handle requests
async function handleRequest(request) {
  const url = new URL(request.url);

  if (url.pathname === "/login" && request.method === "POST") {
    return handleLogin(request);
  } 
  if (url.pathname === "/check-login" && request.method === "GET") {
    return handleCheckLogin(request);
  }
  if (url.pathname === "/logout" && request.method === "POST") {
    return handleLogout(request);
  }

  return new Response("Not Found", { status: 404 });
}

// Handle Login
async function handleLogin(request) {
  const origin = request.headers.get("Origin");
  const rootDomain = getRootDomain(origin);

  if (!allowedRootDomains.includes(rootDomain)) {
    return new Response("Forbidden - Invalid Domain", { status: 403 });
  }

  // Simulate a successful login (In a real app, verify username & password)
  const authToken = "secure_random_token"; // You should generate a real token here

  // Set the authentication cookie
  const response = new Response(JSON.stringify({ success: true, user: "user1" }), { status: 200 });

  response.headers.append("Set-Cookie", `authToken=${authToken}; Path=/; Domain=.${rootDomain}; HttpOnly; Secure; SameSite=None`);

  // Add CORS headers
  addCORSHeaders(response, origin);
  return response;
}

// Handle Check Login
async function handleCheckLogin(request) {
  const origin = request.headers.get("Origin");
  const rootDomain = getRootDomain(origin);

  if (!allowedRootDomains.includes(rootDomain)) {
    return new Response("Forbidden - Invalid Domain", { status: 403 });
  }

  // Check if the user is logged in
  const cookies = request.headers.get("Cookie");
  const loggedIn = cookies && cookies.includes("authToken=secure_random_token");

  const response = new Response(JSON.stringify({ loggedIn, user: loggedIn ? "user1" : null }), { status: loggedIn ? 200 : 401 });

  // Add CORS headers
  addCORSHeaders(response, origin);
  return response;
}

// Handle Logout
async function handleLogout(request) {
  const origin = request.headers.get("Origin");
  const rootDomain = getRootDomain(origin);

  if (!allowedRootDomains.includes(rootDomain)) {
    return new Response("Forbidden - Invalid Domain", { status: 403 });
  }

  // Clear the auth token
  const response = new Response(JSON.stringify({ success: true }), { status: 200 });

  response.headers.append("Set-Cookie", `authToken=; Path=/; Domain=.${rootDomain}; HttpOnly; Secure; SameSite=None; Max-Age=0`);

  // Add CORS headers
  addCORSHeaders(response, origin);
  return response;
}

// Add CORS headers
function addCORSHeaders(response, origin) {
  response.headers.set("Access-Control-Allow-Origin", origin);
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type");
  response.headers.set("Access-Control-Allow-Credentials", "true");
}

// Main Cloudflare Worker event listener
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});
