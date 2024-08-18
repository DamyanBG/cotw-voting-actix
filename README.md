# Cat Of The Week Voting API

This API enables users to vote for their favorite cats in the "Cat Of The Week" contest. Below are the main endpoints and how to use them.

### Endpoints

1. Get a Cat for Voting
 - Endpoint: GET /cats/cat-for-vote
 - Description: Fetch a cat for voting, including a signed URL for its image.
 - Headers: Authorization: Bearer <JWT Token>
 - Responses:
 - 200 OK: Returns the cat's details and image URL.
 - 401 Unauthorized: Missing or invalid token.
 - 500 Internal Server Error: General error.

2. Submit a Vote

 - Endpoint: POST /vote
 - Description: Vote for a cat (like or dislike).
 - Headers: Authorization: Bearer <JWT Token>
 - Body:
json
```
{
  "cat_id": "cat123",
  "vote": "like"
}
```

### Responses:
 - 200 OK: Vote recorded successfully.
 - 400 Bad Request: User already voted.
 - 401 Unauthorized: Missing or invalid token.
 - 500 Internal Server Error: General error.

### Summary

Use the provided endpoints to fetch cats for voting and submit your vote securely using JWT authentication.