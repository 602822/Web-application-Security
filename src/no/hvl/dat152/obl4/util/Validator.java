package no.hvl.dat152.obl4.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class Validator {

	public static String validString(String parameter) {
		return parameter != null ? parameter : "null";
	}

	public static boolean validateUsername(String username) {
		String usernamePattern = "^[A-Za-z0-9]{3,30}$";
		Pattern pattern = Pattern.compile(usernamePattern);
		Matcher matcher = pattern.matcher(username);
		System.out.println( "Valid username: " + matcher.matches());
		return matcher.matches();
	}

	public static boolean validatePhonenumber(String phoneNumber) {
		String phonePattern = "^[0-9]+$";
		Pattern pattern = Pattern.compile(phonePattern);
		Matcher matcher = pattern.matcher(phoneNumber);
		System.out.println("Valid phoneNumber: " +matcher.matches());
		System.out.println("Phone number: " + phoneNumber);
		return matcher.matches();
	}

	public static boolean validateName(String username) {
		String usernamePattern = "^[A-Za-z]{3,30}$";
		Pattern pattern = Pattern.compile(usernamePattern);
		Matcher matcher = pattern.matcher(username);
		System.out.println( "Valid Name: " + matcher.matches());

		return matcher.matches();
	}


	public static  boolean validatePassword(String password) {
		String passwordPattern = "^[A-Za-z0-9]{8,50}$";
		Pattern pattern = Pattern.compile(passwordPattern);
		Matcher matcher = pattern.matcher(password);
		System.out.println("Valid password: " +matcher.matches());

		return matcher.matches();
	}

	public static boolean validateSearch(String searchkey) {
		String searchPattern = "^[A-Za-z]{2,30}$";
		Pattern pattern = Pattern.compile(searchPattern);
		Matcher matcher = pattern.matcher(searchkey);
		System.out.println( "Valid Searchkey: " + matcher.matches());
		return matcher.matches();
	}


	public static String getCookieValue(HttpServletRequest request,
			String cookieName) {

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie c : cookies) {
				if (c.getName().equals(cookieName)) {
					return c.getValue();
				}
			}
		}
		return null;
	}
}
