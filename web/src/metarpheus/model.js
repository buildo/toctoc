
// DO NOT EDIT MANUALLY - metarpheus-generated
/* eslint-disable */
import * as t from 'tcomb';


export const AccessToken = t.declare('AccessToken');

export const Login = t.declare('Login');

export const RefreshToken = t.declare('RefreshToken');

export const TocTocToken = t.declare('TocTocToken');

AccessToken.define(t.struct({
  value: t.String,
  expiresAt: t.Date
}));

Login.define(t.struct({
  username: t.String,
  password: t.String
}));

RefreshToken.define(t.struct({
  value: t.String,
  expiresAt: t.Date
}));

TocTocToken.define(t.struct({
  accessToken: AccessToken,
  refreshToken: RefreshToken
}));
  