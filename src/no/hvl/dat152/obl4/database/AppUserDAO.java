package no.hvl.dat152.obl4.database;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import de.svws_nrw.ext.jbcrypt.BCrypt;
import no.hvl.dat152.obl4.util.Crypto;


public class AppUserDAO {

    public AppUser getAuthenticatedUser(String username, String password) {
        String sql = "SELECT * FROM SecOblig.AppUser WHERE username = ?";
        AppUser user = null;
        Connection c = null;
        PreparedStatement preparedStatement = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            preparedStatement = c.prepareStatement(sql);
            preparedStatement.setString(1, username);
            r = preparedStatement.executeQuery();

            if (r.next()) {
                String storedHashedPassword = r.getString("passhash");


                if (BCrypt.checkpw(password, storedHashedPassword)) {

                    user = new AppUser(
                            r.getString("username"),
                            r.getString("passhash"),
                            r.getString("firstname"),
                            r.getString("lastname"),
                            r.getString("mobilephone"),
                            r.getString("role"));
                }
            }

        } catch (Exception e) {
            System.out.println(e);
        } finally {
            DatabaseHelper.closeConnection(r, preparedStatement, c);
        }

        return user;
    }


    public String getUserClientID(String mobilephone) {

        String sql = "SELECT clientId FROM SecOblig.AppUser"
                + " WHERE mobilephone = '" + mobilephone + "'";


        String clientID = null;

        Connection c = null;
        Statement s = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            s = c.createStatement();
            r = s.executeQuery(sql);

            if (r.next()) {
                clientID = r.getString("clientId");
            }

        } catch (Exception e) {
            System.out.println(e);
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }

        return clientID;
    }

    public boolean clientIDExist(String clientid) {

        String sql = "SELECT clientId FROM SecOblig.AppUser"
                + " WHERE clientId = '" + clientid + "'";


        String clientID = null;

        Connection c = null;
        Statement s = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            s = c.createStatement();
            r = s.executeQuery(sql);

            if (r.next()) {
                clientID = r.getString("clientId");
            }

        } catch (Exception e) {
            System.out.println(e);
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }

        return clientID != null;
    }

    public boolean saveUser(AppUser user) {

        String sql = "INSERT INTO SecOblig.AppUser VALUES ("
                + "'" + user.getUsername() + "', "
                + "'" + user.getPasshash() + "', "
                + "'" + user.getFirstname() + "', "
                + "'" + user.getLastname() + "', "
                + "'" + user.getMobilephone() + "', "
                + "'" + user.getRole() + "')";

        Connection c = null;
        Statement s = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            s = c.createStatement();
            int row = s.executeUpdate(sql);
            if (row >= 0)
                return true;
        } catch (Exception e) {
            System.out.println(e);
            return false;
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }

        return false;
    }

    public List<String> getUsernames() {

        List<String> usernames = new ArrayList<String>();

        String sql = "SELECT username FROM SecOblig.AppUser";

        Connection c = null;
        Statement s = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            s = c.createStatement();
            r = s.executeQuery(sql);

            while (r.next()) {
                usernames.add(r.getString("username"));
            }

        } catch (Exception e) {
            System.out.println(e);
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }

        return usernames;
    }

    public boolean updateUserPassword(String username, String passwordnew) {

        String hashedPassword = Crypto.hashPasswordBcrypt(passwordnew);


        String sql = "UPDATE SecOblig.AppUser SET passhash= ? WHERE username = ?";

        Connection c = null;
        Statement s = null;
        ResultSet r = null;

        try {
            c = DatabaseHelper.getConnection();
            s = c.createStatement();
            PreparedStatement preparedStatement = c.prepareStatement(sql);
            preparedStatement.setString(1, hashedPassword);
            preparedStatement.setString(2, username);
            int row = preparedStatement.executeUpdate();
            System.out.println("Password update successful for " + username);
            if (row >= 0)
                return true;

        } catch (Exception e) {
            System.out.println(e);
            return false;
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }

        return false;
    }


    public boolean updateUserRole(String username, String role) {


        String sql = "UPDATE SecOblig.AppUser SET role = ? WHERE username = ?";

        Connection c = null;
        Statement s = null;
        ResultSet r = null;
        try {
            c = DatabaseHelper.getConnection();
            PreparedStatement preparedStatement = c.prepareStatement(sql);
            preparedStatement.setString(1, role);
            preparedStatement.setString(2, username);


            int row = preparedStatement.executeUpdate();
            System.out.println("Role update successful for " + username + " New role = " + role);
            if (row >= 0)
                return true;

        } catch (Exception e) {
            System.out.println(e);
            return false;
        } finally {
            DatabaseHelper.closeConnection(r, s, c);
        }
        return false;
    }

}

