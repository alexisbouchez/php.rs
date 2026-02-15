<?php
/**
 * php.rs Micro-Framework Demo
 *
 * A REST API for managing items, powered by php.rs with JSON file storage.
 *
 * Routes:
 *   GET  /              - Welcome page
 *   GET  /api/items     - List all items
 *   POST /api/items     - Create a new item (JSON body: {"name": "...", "price": ...})
 *   GET  /api/items/:id - Get a single item
 *   GET  /api/status    - Server status info
 */

// -- Configuration -----------------------------------------------------------

$DB_FILE = dirname(__FILE__) . "/../var/data.json";

// -- Helper functions --------------------------------------------------------

function json_response($data, $code = 200) {
    header("Content-Type: application/json");
    http_response_code($code);
    echo json_encode($data);
}

function load_db($file) {
    if (!file_exists($file)) {
        $initial = json_encode(["items" => [], "next_id" => 1]);
        file_put_contents($file, $initial);
        return json_decode($initial, true);
    }
    $content = file_get_contents($file);
    $data = json_decode($content, true);
    if ($data === null) {
        $initial = json_encode(["items" => [], "next_id" => 1]);
        file_put_contents($file, $initial);
        return json_decode($initial, true);
    }
    return $data;
}

function save_db($file, $data) {
    file_put_contents($file, json_encode($data));
}

// -- Request parsing ---------------------------------------------------------

$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

// Strip query string from URI for routing
$qpos = strpos($uri, "?");
if ($qpos !== false) {
    $path = substr($uri, 0, $qpos);
} else {
    $path = $uri;
}

// Remove leading slash for easier parsing
if (strlen($path) > 1 && $path[0] === "/") {
    $path_trimmed = substr($path, 1);
} else {
    $path_trimmed = $path;
}

$segments = explode("/", $path_trimmed);

// -- Routing -----------------------------------------------------------------

// GET /
if ($path === "/" && $method === "GET") {
    header("Content-Type: text/html; charset=UTF-8");
    echo "<html><head><title>php.rs Demo App</title>";
    echo "<style>body{font-family:sans-serif;max-width:700px;margin:40px auto;padding:0 20px;} ";
    echo "h1{color:#4a90d9;} code{background:#f4f4f4;padding:2px 6px;border-radius:3px;} ";
    echo "pre{background:#f4f4f4;padding:15px;border-radius:5px;overflow-x:auto;}</style></head><body>";
    echo "<h1>Welcome to php.rs!</h1>";
    echo "<p>This is a REST API demo running on the php.rs interpreter.</p>";
    echo "<h2>Available Endpoints</h2>";
    echo "<pre>";
    echo "GET  /api/status       Server status\n";
    echo "GET  /api/items        List all items\n";
    echo "POST /api/items        Create item\n";
    echo "GET  /api/items/:id    Get a single item\n";
    echo "</pre>";
    echo "<h2>Try it</h2>";
    echo "<pre>";
    echo "curl http://localhost:8080/api/status\n";
    echo "curl http://localhost:8080/api/items\n";
    echo "curl -X POST -H 'Content-Type: application/json' \\\n";
    echo "     -d '{\"name\":\"Widget\",\"price\":9.99}' \\\n";
    echo "     http://localhost:8080/api/items\n";
    echo "</pre>";
    echo "<p><small>Powered by php.rs -- PHP " . PHP_VERSION . " compatible interpreter written in Rust</small></p>";
    echo "</body></html>";
}

// GET /api/status
elseif ($path === "/api/status" && $method === "GET") {
    json_response([
        "status" => "ok",
        "engine" => "php.rs",
        "php_version" => PHP_VERSION,
        "server" => $_SERVER['SERVER_SOFTWARE'],
        "time" => date("Y-m-d H:i:s"),
        "timestamp" => time()
    ]);
}

// GET /api/items
elseif ($path === "/api/items" && $method === "GET") {
    $db = load_db($DB_FILE);
    $items = $db["items"];
    json_response(["items" => $items, "count" => count($items)]);
}

// POST /api/items
elseif ($path === "/api/items" && $method === "POST") {
    // Read JSON body from $_BODY (php.rs provides raw POST body here)
    $body = $_BODY;
    $input = json_decode($body, true);

    if ($input === null) {
        json_response(["error" => "Invalid JSON body"], 400);
    } elseif (!isset($input["name"])) {
        json_response(["error" => "Missing required field: name"], 400);
    } else {
        $db = load_db($DB_FILE);
        $id = $db["next_id"];

        $item = [
            "id" => $id,
            "name" => $input["name"],
            "price" => isset($input["price"]) ? $input["price"] : 0,
            "created_at" => date("Y-m-d H:i:s")
        ];

        // Work around nested array push limitation: rebuild items array
        $items = $db["items"];
        $items[] = $item;
        $db["items"] = $items;
        $db["next_id"] = $id + 1;

        save_db($DB_FILE, $db);
        json_response(["item" => $item, "message" => "Item created"], 201);
    }
}

// GET /api/items/:id
elseif (count($segments) === 3 && $segments[0] === "api" && $segments[1] === "items" && $method === "GET") {
    $id = intval($segments[2]);
    $db = load_db($DB_FILE);
    $found = null;
    $items = $db["items"];
    $i = 0;
    while ($i < count($items)) {
        if ($items[$i]["id"] === $id) {
            $found = $items[$i];
        }
        $i = $i + 1;
    }

    if ($found !== null) {
        json_response(["item" => $found]);
    } else {
        json_response(["error" => "Item not found", "id" => $id], 404);
    }
}

// 404 - Route not found
else {
    json_response([
        "error" => "Not Found",
        "method" => $method,
        "path" => $path
    ], 404);
}
