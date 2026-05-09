import java.sql.Statement;

public class Vulnerable {
    public void consultaInsegura(Statement statement, String query) throws Exception {
        // Posible SQL Injection detectada por SAST
        statement.executeQuery(query);
    }
}