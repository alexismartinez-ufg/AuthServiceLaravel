<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Exceptions\HttpResponseException;
use Exception;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;


class AuthController extends Controller
{
    // Register API
    public function register(Request $request){
        try {
            // Data validation with additional rules
            $validator = Validator::make($request->all(), [
                "name" => "required|min:3",
                "email" => "required|email|unique:users",
                "password" => "required|min:3",
            ]);
    
            // Check if the validation fails
            if ($validator->fails()) {
                throw new HttpResponseException(response()->json([
                    "status" => false,
                    "message" => "Invalid user data",
                    "errors" => $validator->errors()
                ], 422));
            }
    
            // Data save        
            User::create([
                "name" => $request->name,
                "email" => $request->email,
                "password" => Hash::make($request->password)
            ]);
    
            // Response
            return response()->json([
                "status" => true,
                "message" => "User created successfully"
            ]);
        } catch (HttpResponseException $e) {
            return response()->json([
                "status" => false,
                "message" => "Validation error occurred",
                "errors" => json_decode($e->getResponse()->getContent(), true)
            ], $e->getResponse()->status());
        } catch (Exception $e) {
            return response()->json([
                "status" => false,
                "message" => "An error occurred while creating the user",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    // Login API
    public function login(Request $request){
        
        try {
            $request->validate([
                "email" => "required|email",
                "password" => "required|min:3" // Asegura una longitud mínima para la contraseña
            ]);
    
            $credentials = $request->only(['email', 'password']);
    
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    "status" => false,
                    "message" => "Invalid login details"
                ], 401); // Código de estado HTTP para "No autorizado"
            }
    
            return response()->json([
                "status" => true,
                "message" => "User logged in successfully",
                "token" => $token
            ]);
        } catch (ValidationException $e) {
            // Captura excepciones de validación y devuelve una respuesta adecuada
            return response()->json([
                "status" => false,
                "message" => "Validation errors",
                "errors" => $e->errors()
            ], 422); // Código de estado HTTP para "Entidad no procesable"
        } catch (\Exception $e) {
            // Maneja cualquier otra excepción y devuelve un error general
            return response()->json([
                "status" => false,
                "message" => "An error occurred during login",
                "error" => $e->getMessage()
            ], 500); // Código de estado HTTP para "Error interno del servidor"
        }
    }

    // Profile API
    public function profile(){
        try{
            $user = auth()->user();
    
            if (!$user) {
                return response()->json([
                    "status" => false,
                    "message" => "User not authenticated"
                ], 401); // Código de estado HTTP 401 para no autenticado
            }
        
            // Seleccionar los datos del usuario que deseas exponer
            $userData = [
                'name' => $user->name,
                'email' => $user->email,
                // Agrega cualquier otro campo que consideres necesario y seguro de exponer
            ];
        
            return response()->json([
                "status" => true,
                "message" => "Profile data",
                "user" => $userData
            ]);
        }catch (\Exception $e) {
            // Maneja cualquier otra excepción y devuelve un error general
            return response()->json([
                "status" => false,
                "message" => "An error occurred during get Profile",
                "error" => $e->getMessage()
            ], 500); // Código de estado HTTP para "Error interno del servidor"
        }
    }
    

    // Refresh Token API
    public function refreshToken(){
        try {
            $newToken = auth()->refresh(); // Intenta refrescar el token
    
            return response()->json([
                "status" => true,
                "message" => "New access token generated",
                "token" => $newToken
            ]);
        } catch (TokenInvalidException $e) {
            return response()->json([
                "status" => false,
                "message" => "Token is invalid"
            ], 401);
        } catch (TokenExpiredException $e) {
            return response()->json([
                "status" => false,
                "message" => "Token has expired and can no longer be refreshed"
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                "status" => false,
                "message" => "Could not refresh the token",
                "error" => $e->getMessage()
            ], 500);
        }
    }


    // Logout API
    public function logout(){
        try {
            auth()->logout(); // Intenta cerrar la sesión
    
            return response()->json([
                "status" => true,
                "message" => "User logged out successfully"
            ]);
        } catch (\Exception $e) {
            return response()->json([
                "status" => false,
                "message" => "Could not log the user out",
                "error" => $e->getMessage()
            ], 500);
        }
    }

}
