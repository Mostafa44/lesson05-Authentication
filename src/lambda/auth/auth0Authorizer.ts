import { CustomAuthorizerEvent, CustomAuthorizerHandler, CustomAuthorizerResult, } from 'aws-lambda'
import 'source-map-support/register'
import * as AWS from 'aws-sdk';
//import * as middy from 'middy'
//import { secretsManager } from 'middy/middlewares'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const secretId = process.env.AUTH_0_SECRET_ID
const secretField = process.env.AUTH_0_SECRET_FIELD
const client = new AWS.SecretsManager();


//Cache secrete if lambda is reused
let cachedSecret: string;

//export const handler = middy(async (event: CustomAuthorizerEvent, context): Promise<CustomAuthorizerResult> => {
export const handler: CustomAuthorizerHandler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {


  try {
    const decodedToken = await verifyToken(event.authorizationToken);
    // verifyToken(
    // event.authorizationToken,
    //  context.AUTH0_SECRET[secretField]
    //)
    console.log('User was authorized', decodedToken);

    return {
      principalId: decodedToken.sub,
      //principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User was not authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
  //})
}
//function verifyToken(authHeader: string, secret: string): JwtToken {
async function verifyToken(authHeader: string): Promise<JwtToken> {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]
  console.log("token is ", token);
  // if (token !== '123') {
  //   throw new Error('Invalid token');
  // }
  const secretObject = await getSecret();
  const secret = secretObject[secretField];
  return verify(token, secret) as JwtToken
}
async function getSecret() {
  if (cachedSecret) return cachedSecret;
  const data = await client.getSecretValue({ SecretId: secretId }).promise();
  cachedSecret = data.SecretString;
  return JSON.parse(cachedSecret);
}
// handler.use(
//   secretsManager({
//     cache: true,
//     cacheExpiryInMillis: 60000,
//     // Throw an error if can't read the secret
//     throwOnFailedCall: true,
//     secrets: {
//       AUTH0_SECRET: secretId
//     }
//   })
// )
