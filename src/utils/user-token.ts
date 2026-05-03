export interface JWTClaims {
    iss: string;
    sub: string;
    exp: number;
    iat: number;
    client_id: string;
    scope: string;
    type?: "access" | "refresh";
    email?: string;
    email_verified?: string;
    family_name?: string;
    given_name?: string;
    name?: string;
    picture?: string;
}

export interface BaseClaims {
    iss: string;
    sub: string;
    iat: number;
    client_id: string;
    scope: string;
}
