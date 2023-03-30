/*
This versio is intentionally worse that the pervious version. 
t is poorly structured, and contains injection attacks.
*/

package workshop07_code;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 *
 * @author comp3310 with input from sqlitetutorial.net
 *
 *         Note, this is not a fully correct solution to the week 5 workshop.
 *         It still contains quite a few issues to be found.
 */
public class App {
    static {
        // must set before the Logger
        // loads logging.properties from the classpath
        try (FileInputStream logFile = new FileInputStream(
                "resources/logging.properties")) { // resources\logging.properties
            LogManager.getLogManager().readConfiguration(logFile);
        } catch (SecurityException | IOException e1) {
            e1.printStackTrace();
        }
    }

    private static final Logger logger = Logger.getLogger(App.class.getName());

    /**
     * @param args the command line arguments
     * @throws SQLException
     */
    public static void main(String[] args)  {
        SQLiteConnectionManager wordleDatabaseConnection = new SQLiteConnectionManager("words.db");

        wordleDatabaseConnection.createNewDatabase("words.db");
        if (wordleDatabaseConnection.checkIfConnectionDefined()) {
            logger.log(Level.INFO, "Wordle created and connected.");
        } else {
            logger.log(Level.WARNING, "Not able to connect. Sorry!");
            return;
        }
        if (wordleDatabaseConnection.createWordleTables()) {
            logger.log(Level.INFO, "Wordle structures in place.");
        } else {
            logger.log(Level.WARNING, "Not able to launch. Sorry!");
            return;
        }

        // let's add some words to valid 4 letter words from the data.txt file

        try (BufferedReader br = new BufferedReader(new FileReader("resources/data.txt"))) {
            String line;
            int i = 1;
            while ((line = br.readLine()) != null) {
                wordleDatabaseConnection.addValidWord(i, line);
                String msg = String.format("Added %s to db", line);
                logger.log(Level.INFO, msg);
                i++;
            }

        } catch (IOException e) {
            logger.log(Level.SEVERE, "Not able to load . Sorry!", e);
            return;
        }

        // let's get them to enter a word

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter a 4 letter word for a guess or q to quit: ");
            String guess = scanner.nextLine();

            while (!guess.equals("q")) {
                System.out.println("You've guessed '" + guess + "'.");
                String sql = "SELECT count(id) as total FROM validWords WHERE word like'" + guess
                        + "';";
                String url = wordleDatabaseConnection.getDatabaseURL();
                try (Connection conn = DriverManager.getConnection(url);
                        PreparedStatement stmt = conn.prepareStatement(sql)) {
                    ResultSet resultRows = stmt.executeQuery();
                    if (resultRows.next() && resultRows.getInt("total")>0) {
                        System.out.println("Success! It is in the the list.\n");
                    } else {
                        System.out.println("Sorry. This word is NOT in the the list.\n");
                    }
                } catch (SQLException e) {
                    logger.log(Level.WARNING, e.getMessage());
                }

                System.out.print("Enter a 4 letter word for a guess or q to quit: ");
                guess = scanner.nextLine();
            }
        } catch (NoSuchElementException | IllegalStateException e) {
            logger.log(Level.WARNING, "Could not read.", e);
        }
    }
}
