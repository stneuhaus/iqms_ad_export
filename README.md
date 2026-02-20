# AD Group Export Tool


### How to Get a Bearer Token

You can obtain a bearer token for testing from the Microsoft Graph Explorer:

1. Go to https://developer.microsoft.com/en-us/graph/graph-explorer
2. Sign in with your Microsoft account
3. In the query box, enter: `https://graph.microsoft.com/v1.0/me`
4. Click **"Run query"**
5. Click on the **"Access token"** tab (as shown in the image below)
6. Copy the token displayed
7. Paste this token into your `.env` file as the `BEARER_TOKEN` value

![Graph Explorer - Access Token Tab](docs/graph-explorer-access-token.png)

**Note:** Tokens from Graph Explorer are temporary and expire after a short period. For production use, you should implement proper OAuth authentication or use a service principal with appropriate permissions.
