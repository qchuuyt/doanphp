<?php
require_once 'config.php';

$input = json_decode(file_get_contents('php://input'), true);
$method = $_SERVER['REQUEST_METHOD'];
$path = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '/';

switch ($path) {
    case '/register':
        if ($method === 'POST') register($input, $conn);
        break;
    case '/login':
        if ($method === 'POST') login($input, $conn);
        break;
    case '/profile':
        if ($method === 'GET') getProfile($conn);
        break;
    case '/roles':
        if ($method === 'GET') getRoles($conn);
        break;
    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
        break;
}

function register($input, $conn) {
    if (!isset($input['email']) || !isset($input['username']) || !isset($input['sdt']) || !isset($input['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Email, username, phone number, and password are required']);
        return;
    }
    $email = $input['email'];
    $username = $input['username'];
    $sdt = $input['sdt'];
    $password = password_hash($input['password'], PASSWORD_DEFAULT);
    $roleId = 1; // Default 'user'
    
    if (!preg_match('/^[0-9]{10}$/', $sdt)) {
        http_response_code(400);
        echo json_encode(['error' => 'Phone number must be exactly 10 digits']);
        return;
    }

    try {
        $stmt = $conn->prepare("INSERT INTO users (email, username, sdt, password, role_id) VALUES (:email, :username, :sdt, :password, :role_id)");
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':sdt', $sdt);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':role_id', $roleId);
        $stmt->execute();
        http_response_code(201);
        echo json_encode(['message' => 'Registration successful']);
    } catch(PDOException $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Email or username already exists']);
    }
}

function login($input, $conn) {
    if (!isset($input['email']) || !isset($input['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        return;
    }
    $email = $input['email'];
    $password = $input['password'];
    
    $stmt = $conn->prepare("SELECT u.id, u.email, u.username, u.sdt, u.password, u.role_id, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])) {
        $token = generateToken($user['id'], $user['role_id']);
        echo json_encode([
            'message' => 'Login successful',
            'token' => $token,
            'role' => $user['role_name'],
            'username' => $user['username'],
            'sdt' => $user['sdt']
        ]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
    }
}

function getProfile($conn) {
    $headers = apache_request_headers();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Token required']);
        return;
    }
    $token = str_replace('Bearer ', '', $headers['Authorization']);
    $userData = verifyToken($token);
    
    if (!$userData) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or expired token']);
        return;
    }
    $stmt = $conn->prepare("SELECT u.id, u.email, u.username, u.sdt, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = :id");
    $stmt->bindParam(':id', $userData['user_id']);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) echo json_encode($user);
    else {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
    }
}

function getRoles($conn) {
    $stmt = $conn->prepare("SELECT id, name, description FROM roles");
    $stmt->execute();
    $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($roles);
}
?>