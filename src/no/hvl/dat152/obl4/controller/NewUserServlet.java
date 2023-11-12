package no.hvl.dat152.obl4.controller;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import no.hvl.dat152.obl4.database.AppUser;
import no.hvl.dat152.obl4.database.AppUserDAO;
import no.hvl.dat152.obl4.util.Crypto;
import no.hvl.dat152.obl4.util.Role;
import no.hvl.dat152.obl4.util.Validator;

@WebServlet("/newuser")
public class NewUserServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response) throws ServletException, IOException {

        int len = request.getRequestURL().length();
        String dicturi = request.getRequestURL().substring(0, len - 7) + "v003/";

        request.setAttribute("dictconfig", dicturi);
        request.getRequestDispatcher("newuser.jsp").forward(request, response);
    }

    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {

        boolean successfulRegistration = false;


        String username = request
                .getParameter("username");
        String password = request
                .getParameter("password");
        String confirmedPassword = request
                .getParameter("confirm_password");
        String firstName = request
                .getParameter("first_name");
        String lastName = request
                .getParameter("last_name");
        String mobilePhone = request
                .getParameter("mobile_phone");
        String preferredDict = request
                .getParameter("dicturl");

        System.out.println("dicturl: " + Validator.validString(request
                .getParameter("dicturl")));

        AppUser user = null;
        if (password.equals(confirmedPassword) && Validator.validateUsername(username)
                && Validator.validatePassword(password) && Validator.validateName(firstName)
                && Validator.validateName(lastName) && Validator.validatePhonenumber(mobilePhone)) {

            AppUserDAO userDAO = new AppUserDAO();

            user = new AppUser(username, Crypto.hashPasswordBcrypt(password),
                    firstName, lastName, mobilePhone, Role.USER.toString());

            successfulRegistration = userDAO.saveUser(user);
        }

        if (successfulRegistration) {
            String csrfToken = Crypto.generateRandomToken();
            HttpSession session = request.getSession(true);
            session.setAttribute("csrfToken",csrfToken);
            session.setAttribute("user",user);
          //  request.getSession().setAttribute("user", user);
            Cookie dicturlCookie = new Cookie("dicturl", preferredDict);
            dicturlCookie.setMaxAge(60 * 10);
            response.addCookie(dicturlCookie);

            response.sendRedirect("searchpage");

        } else {
            request.setAttribute("message", "Registration failed!");
            request.getRequestDispatcher("newuser.jsp").forward(request,
                    response);
        }
    }

}
