import { NextRequest, NextResponse } from "next/server";
import { verifyToken } from "./lib/authJWT";

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const decodedToken = await verifyToken(request);

  // Pages that require authentication. Unauthenticated users are sent to login
  // instead of relying on a client-side redirect after the page has loaded.
  const protectedRoutes = ["/links"];

  if (!decodedToken && protectedRoutes.includes(pathname)) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // Signups disabled for now — remove this to re-enable the signup page.
  if (pathname === "/signup") {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // If the user is authenticated and trying to access login or signup

  if (decodedToken && (pathname === "/login" || pathname === "/signup")) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  if (pathname === "/api/logout") {
    const response = NextResponse.next();

    // Clear the token cookie
    // Must mirror the attributes used when the cookie was set in the login
    // route (path '/', secure, sameSite 'none') so the browser clears it.
    // No `domain` is set on login, so none is set here; an invalid domain
    // (e.g. a full URL) makes the Set-Cookie attribute a no-op.
    response.cookies.set("token", "", {
      httpOnly:true,
      expires: new Date(0),
      maxAge: 0,
      path: '/',
      secure: true,
      sameSite: 'none',
    });

    return response;
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/links", "/login", "/signup", "/api/logout"],
};
