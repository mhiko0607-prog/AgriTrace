<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

/**
 * Controller: ApiController
 * 
 * Automatically generated via CLI.
 */
class ApiController extends Controller {
    private $user_id;

    public function __construct()
    {
        parent::__construct();
        $this->call->database();
        $this->call->library('api');
    }
    
    public function login()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('login', 5, 60); // 5 requests per minute

        $input = $this->api->body();

        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';

        if (empty($username) || empty($password)) {
            $this->api->respond_error('Username and password are required.', 400);
        }
        $user = $this->db->raw(
            "SELECT id, username, password, role FROM users WHERE username = ? LIMIT 1",
            [$username]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->api->respond_error('Invalid username or password.', 401);
        }

        $tokens = $this->api->issue_tokens([
            'id' => $user['id'],
            'role' => $user['role']
        ]);

        $this->api->respond([
            'message' => 'Login successful.',
            'tokens' => $tokens
        ]);
    }

    public function refresh()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('refresh', 20, 60);

        $input = $this->api->body();
        $refresh_token = trim($input['refresh_token'] ?? '');

        if (empty($refresh_token)) {
            $this->api->respond_error('Refresh token is required.', 422);
        }
        $this->api->refresh_access_token($refresh_token);
    }

    public function logout()
    {
        $this->api->require_method('POST');

        $input = $this->api->body();
        $refresh_token = trim($input['refresh_token'] ?? '');

        if (empty($refresh_token)) {
            $this->api->respond_error('Refresh token is required.', 422);
        }

        $this->api->revoke_refresh_token($refresh_token);
        $this->api->respond(['message' => 'Logged out successfully.']);
    }

    public function create()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit('register', 5, 300); // 10 requests per minute

        $input = $this->api->body();

        $username = is_string($input['username'] ?? null) ? trim($input['username']) : '';
        $email = is_string($input['email'] ?? null) ? trim($input['email']) : '';
        $password = $input['password'] ?? '';
        $role = 'user';

        if (array_key_exists('role', $input)) {
            if (!is_string($input['role'])) {
                $this->api->respond_error('Role must be a string.', 422);
            }

            $requested_role = strtolower(trim($input['role']));
            if (!in_array($requested_role, ['user', 'admin'], true)) {
                $this->api->respond_error('Invalid role.', 422);
            }

            $role = $requested_role;
        }

        // Validation
        if (empty($username) || empty($email) || empty($password)) {
            $this->api->respond_error('Username, email, and password are required.', 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error('Invalid email format.', 422);
        }

        if(strlen($password) < 8) {
            $this->api->respond_error('Password must be at least 8 characters long.', 422);
        }

        // Check if user exist
        $existing = $this->db->raw(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
            [$username, $email]
        )->fetch(PDO::FETCH_ASSOC);

        if ($existing) {
            $this->api->respond_error('Username or email already exists.', 422);
        }

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $this->db->raw(
            "INSERT INTO users (username, email, password, role, created_at)
            VALUES (?, ?, ?, ?, NOW())",
            [$username, $email, $hashed_password, $role]
        );

        $new_id = $this->db->last_id();

        $this->api->respond([
            'message' => 'User created successfully.',
            'user_id' => $new_id
        ], 201);
    }

    public function list()
    {
        $this->api->require_method('GET');
        $auth = $this->api->require_jwt();

        if ($auth['role'] !== 'admin') {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $users = $this->db->raw(
            'SELECT id, username, email, role, created_at FROM users ORDER BY id'
        )->fetchAll(PDO::FETCH_ASSOC);

        $this->api->respond(['data' => $users]);
    }

    public function profile()
    {
        $this->api->require_method('GET');
        $auth = $this->api->require_jwt();

        $this->user_id = $auth['sub'];
        $user = $this->db->raw(
            "SELECT id, username, first_name, last_name, middle_name, address, email, role, created_at FROM users WHERE id = ? LIMIT 1",
            [$this->user_id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $this->api->respond($user);
    }

    public function update($id)
    {
        $this->api->require_method('PUT');
        $auth = $this->api->require_jwt();
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if ($id === false) {
            $this->api->respond_error('Invalid user ID.', 422);
        }

        $user = $this->db->raw(
            'SELECT id, username, email, role, created_at FROM users WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $is_admin = ($auth['role'] ?? '') === 'admin';
        if (!$is_admin && (string) $auth['sub'] !== (string) $user['id']) {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $input = $this->api->body();
        $updates = [];
        $values = [];

        if (array_key_exists('username', $input)) {
            if (!is_string($input['username'])) {
                $this->api->respond_error('Username must be a string.', 422);
            }
            $username = trim($input['username']);
            if ($username === '') {
                $this->api->respond_error('Username cannot be empty.', 422);
            }
            $updates[] = 'username = ?';
            $values[] = $username;
            $user['username'] = $username;
        }

        if (array_key_exists('email', $input)) {
            if (!is_string($input['email'])) {
                $this->api->respond_error('Email must be a string.', 422);
            }
            $email = trim($input['email']);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->api->respond_error('Invalid email format.', 422);
            }
            $updates[] = 'email = ?';
            $values[] = $email;
            $user['email'] = $email;
        }

        if (array_key_exists('role', $input)) {
            if (!$is_admin) {
                $this->api->respond_error('Only administrators can change user roles.', 403);
            }
            if (!is_string($input['role'])) {
                $this->api->respond_error('Role must be a string.', 422);
            }
            $role = strtolower(trim($input['role']));
            if (!in_array($role, ['user', 'admin', 'editor'], true)) {
                $this->api->respond_error('Invalid role.', 422);
            }
            $updates[] = 'role = ?';
            $values[] = $role;
            $user['role'] = $role;
        }

        if (!$updates) {
            $this->api->respond_error('Provide a username, email, or role to update.', 422);
        }

        $duplicate = $this->db->raw(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id <> ? LIMIT 1',
            [$user['username'], $user['email'], $id]
        )->fetch(PDO::FETCH_ASSOC);

        if ($duplicate) {
            $this->api->respond_error('Username or email already exists.', 422);
        }

        $values[] = $id;
        $this->db->raw(
            'UPDATE users SET ' . implode(', ', $updates) . ', updated_at = NOW() WHERE id = ?',
            $values
        );

        $user['id'] = $id;
        $this->api->respond([
            'message' => 'User updated successfully.',
            'user' => $user
        ]);
    }

    public function delete($id)
    {
        $this->api->require_method('DELETE');
        $auth = $this->api->require_jwt();
        $id = filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if ($id === false) {
            $this->api->respond_error('Invalid user ID.', 422);
        }

        $user = $this->db->raw(
            'SELECT id FROM users WHERE id = ? LIMIT 1',
            [$id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error('User not found.', 404);
        }

        $is_admin = ($auth['role'] ?? '') === 'admin';
        if (!$is_admin && (string) $auth['sub'] !== (string) $user['id']) {
            $this->api->respond_error('Unauthorized access.', 403);
        }

        $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$id]);
        $this->db->raw('DELETE FROM users WHERE id = ?', [$id]);

        $this->api->respond(['message' => 'User deleted successfully.']);
    }
}