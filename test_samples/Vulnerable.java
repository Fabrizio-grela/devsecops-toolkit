import java.sql.*;

public class Vulnerable {
    public void execute(String user) throws Exception {
        // 1. Esto debería disparar la alerta de SQL Injection
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + user); 

        // 2. Esto debería disparar la alerta de RCE (Comandos de sistema)
        Runtime.getRuntime().exec("ping " + user);
    }
}