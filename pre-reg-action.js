exports.onExecutePreUserRegistration = async (event, api) => {
    const visitorId = event.request.body['ulp-visitorId'];
    const requestId = event.request.body['ulp-requestId'];
    
    const naughty = await checkUserBeingNaughty(visitorId, event, api);
    
    if (naughty) {
      api.access.deny("invalid_payload", "Multiple trials as a visitor are not supported. Please use the current trial or upgrade to a paid account!");
    } else {
      api.user.setAppMetadata("visitorId", visitorId);
    }
  };
  
  // Function to check if a user already exists with the same visitorId
  async function checkUserBeingNaughty(visitorId, event, api) {
    const accessToken = api.cache.get("MGMT_API_TOKEN") ?? await getManagementApiToken(event, api);
  
    // Define the Management API endpoint for querying users
    const managementApiEndpoint = `https://${event.secrets.AUTH0_DOMAIN}/api/v2/users`;
  
    // Construct the query to find users with the same visitorId in their app_metadata
    const metadataQuery = encodeURIComponent(`app_metadata.visitorId:"${visitorId}"`);
    const url = `${managementApiEndpoint}?q=${metadataQuery}&search_engine=v3`;
  
    try {
      const response = await axios.get(url, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });
  
      // Check if any user has the same visitorId
      const users = response.data;
      return users.length > 0;
  
    } catch (error) {
      console.error('Failed to query users:', error.response ? error.response.data : error.message);
      return false; // Default to not naughty if there's an error in the query
    }
  }
  
  // Function to get the Management API token
  async function getManagementApiToken(event, api) {
    const domain = event.secrets.AUTH0_DOMAIN;
    const clientId = event.secrets.CLIENT_ID;
    const clientSecret = event.secrets.CLIENT_SECRET;
    const audience = `https://${domain}/api/v2/`;
  
    try {
      const response = await axios.post(`https://${domain}/oauth/token`, {
        client_id: clientId,
        client_secret: clientSecret,
        audience: audience,
        grant_type: 'client_credentials'
      }, {
        headers: {
          'Content-Type': 'application/json'
        }
      });
  
      const tokenData = response.data;
      api.cache.set("MGMT_API_TOKEN", tokenData.access_token);
      return tokenData.access_token;
    } catch (error) {
      throw new Error(`Failed to obtain access token: ${error.response ? error.response.data : error.message}`);
    }
  }