package no.hvl.dat152.obl4.controller;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import no.hvl.dat152.obl4.database.AppUser;
import no.hvl.dat152.obl4.database.AppUserDAO;
import no.hvl.dat152.obl4.util.Validator;


@WebServlet("/updatepassword")
public class UpdatePasswordServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response) throws ServletException, IOException {
        // check that the user has a valid session
        if (RequestHelper.isLoggedIn(request))
            request.getRequestDispatcher("updatepassword.jsp").forward(request, response);
        else {
            request.setAttribute("message", "Session has expired. Login again!");
            request.getRequestDispatcher("login").forward(request, response);
        }
    }

    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {


        request.removeAttribute("message");


        response.setHeader("Content-Security-Policy", "default-src 'self'");

        boolean successfulPasswordUpdate = false;

        String passwordnew = request
                .getParameter("passwordnew");

        String confirmedPasswordnew = request
                .getParameter("confirm_passwordnew");

        String requestCsrfToken = request.getParameter("csrfToken");
        String sessionCsrfToken = (String) request.getSession().getAttribute("csrfToken");


        if (RequestHelper.isLoggedIn(request)) {

            AppUser user = (AppUser) request.getSession().getAttribute("user");

            AppUserDAO userDAO = new AppUserDAO();

            if (passwordnew.equals(confirmedPasswordnew) && Validator.validatePassword(passwordnew)
                    && Validator.validatePassword(confirmedPasswordnew)) {

                if(requestCsrfToken == null  || !requestCsrfToken.equals(sessionCsrfToken)) {
                    request.setAttribute("message3", "Token missing or invalid");
                    request.getRequestDispatcher("login.jsp").forward(request,response);
                } else {
                    successfulPasswordUpdate = userDAO.updateUserPassword(user.getUsername(), passwordnew);
                    request.getSession().removeAttribute("csrfToken"); //Prevent reuse of CSRF Token
                }

                if (successfulPasswordUpdate) {
                    request.getSession().invalidate(); // invalidate current session and force user to login again
                    request.setAttribute("message", "Password successfully updated. Please login again!");
                    response.sendRedirect("login");

                } else {
                    request.setAttribute("message", "Password update failed!");
                    request.getRequestDispatcher("updatepassword.jsp").forward(request,
                            response);
                }
            } else {
                request.setAttribute("message", "Invalid Password Try again!");
                request.getRequestDispatcher("updatepassword.jsp").forward(request,
                        response);
            }

        } else {
            request.getSession().invalidate();
            request.getRequestDispatcher("index.html").forward(request,
                    response);
        }

    }

}
