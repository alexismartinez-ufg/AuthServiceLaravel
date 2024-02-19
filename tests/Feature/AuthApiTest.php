<?php

use Illuminate\Foundation\Testing\RefreshDatabase;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

uses(RefreshDatabase::class);

it('a user can register successfully', function () {
    $response = $this->postJson('/api/register', [
        'name' => 'Test User',
        'email' => 'testuser@example.com',
        'password' => 'password',
    ]);

    $response->assertStatus(200)
             ->assertJson([
                 'status' => true,
                 'message' => 'User created successfully',
             ]);
});

it('registration fails due to validation errors', function () {
    $response = $this->postJson('/api/register', [
        'name' => '', // Empty name to trigger validation error
        'email' => 'not-an-email',
        'password' => 'pw',
    ]);

    $response->assertStatus(422)
             ->assertJson([
                 'status' => false,
                 'message' => 'Validation error occurred',
                 'errors' => [
                    'status' => false,
                    'message' => 'Invalid user data',
                    'errors' => [
                        'name' => ['The name field is required.'],
                        'email' => ['The email field must be a valid email address.'],
                        'password' => ['The password field must be at least 3 characters.'],
                    ],
                 ],
             ]);
});




it('a user can login successfully', function () {
    // Primero, necesitas un usuario en la base de datos para este test
    $user = User::create([
        'name' => 'Test User',
        'email' => 'testlogin@example.com',
        'password' => Hash::make('password'),
    ]);

    $response = $this->postJson('/api/login', [
        'email' => 'testlogin@example.com',
        'password' => 'password',
    ]);

    $response->assertStatus(200)
             ->assertJson([
                 'status' => true,
                 'message' => 'User logged in successfully',
             ]);
});

it('user cannot login with invalid credentials', function () {
    $response = $this->postJson('/api/login', [
        'email' => 'wronguser@example.com',
        'password' => 'wrongpassword',
    ]);

    $response->assertStatus(401)
             ->assertJson([
                 'status' => false,
                 'message' => 'Invalid login details',
             ]);
});

it('authenticated user can access profile', function () {
    // Asumiendo que tienes un usuario y un mecanismo de autenticación establecido
    $user = User::factory()->create(); // Usar User factory para crear un usuario
    $token = JWTAuth::fromUser($user);

    $response = $this->withHeaders(['Authorization' => "Bearer {$token}"])
                     ->getJson('/api/profile');

    $response->assertStatus(200)
             ->assertJson([
                 'status' => true,
                 'message' => 'Profile data',
             ]);
});

it('unauthenticated user cannot access profile', function () {
    $response = $this->getJson('/api/profile');

    $response->assertStatus(401)
             ->assertJson([
                 'message' => 'Unauthenticated.',
             ]);
});

