<?php
require 'database.php';

session_start();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['email']) && isset($_POST['password'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'];
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['status' => 'error', 'message' => 'Email no válido']);
            exit;
        }
        
        try {
            // Verificar si el usuario ya existe
            $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                // Usuario existe - en este caso simplemente aceptamos el login
                echo json_encode(['status' => 'success', 'message' => 'Redirigiendo...']);
            } else {
                // Insertar nuevo usuario CON CONTRASEÑA EN TEXTO PLANO
                $stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (:email, :password)");
                $stmt->bindParam(':email', $email);
                $stmt->bindParam(':password', $password); // Almacenamiento directo
                $stmt->execute();
                
                echo json_encode([
                    'status' => 'success', 
                    'message' => 'Usuario registrado y redirigiendo...'
                ]);
            }
        } catch(PDOException $e) {
            echo json_encode(['status' => 'error', 'message' => 'Error en la base de datos: ' . $e->getMessage()]);
        }
    }
}
?>