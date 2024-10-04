<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use OpenApi\Annotations as OA;


class AuthController extends Controller
{
    // Constructeur avec middleware pour protéger les routes sauf login et register
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

   
    public function register(Request $request)
    {
        // Valider les données de la requête
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        // Retourner une réponse avec les erreurs de validation si elles existent
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // Créer un nouvel utilisateur avec les données validées et crypter le mot de passe
        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        // Retourner une réponse avec les informations de l'utilisateur créé
        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    
    public function login(Request $request)
    {
        // Logic for login will be implemented here
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (!$token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    /**
     * Create a new token.
     *
     * @param  string $token
     * @return \Illuminate\Http\JsonResponse
     */
    public function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => 3600,
            'user' => auth()->user()
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/auth/profile",
     *     summary="Get user profile",
     *     @OA\Response(
     *         response=200,
     *         description="User profile"
     *     )
     * )
     */
    public function profile()
    {
        return response()->json(auth()->user());
    }

    /**
     * @OA\Post(
     *     path="/api/auth/logout",
     *     summary="Logout a user",
     *     @OA\Response(
     *         response=200,
     *         description="User logged out"
     *     )
     * )
     */
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'User logged out']);
    }
}