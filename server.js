const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const bodyParser = require("body-parser");
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLNonNull,
} = require("graphql");
const jwt = require("jsonwebtoken");
const fs = require("fs/promises");
const cors = require("cors");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const PORT = 8001;
const SECRET_KEY = "qazxswedc";
const expiresIn = "1h";

// Sample user database saved in a JSON file
const userdbPath = "./users.json";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

// Check if the user exists in database
async function isAuthenticated({ email, password }) {
  try {
    const rawData = await fs.readFile(userdbPath);
    const data = JSON.parse(rawData.toString());
    return data.users.some(
      (user) => user.email === email && user.password === password
    );
  } catch (error) {
    return false;
  }
}

// Define a new GraphQLObjectType for the token
const TokenType = new GraphQLObjectType({
  name: "Token",
  fields: {
    access_token: { type: GraphQLString },
  },
});

const RootQueryType = new GraphQLObjectType({
  name: "Query",
  fields: {
    auth: {
      type: TokenType,
      resolve: async (_, args, context) => {
        if (!context.req || !context.req.user || !context.req.user.token) {
          throw new Error("Unauthorized");
        }

        const user = context.req.user;
        return { access_token: user.token };
      },
    },
  },
});

const RootMutationType = new GraphQLObjectType({
  name: "Mutation",
  fields: {
    register: {
      type: TokenType,
      args: {
        email: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
      },
      resolve: async (_, args) => {
        const { email, password } = args;

        if (await isAuthenticated({ email, password })) {
          throw new Error("User already exists");
        }

        try {
          const rawData = await fs.readFile(userdbPath);
          const data = JSON.parse(rawData.toString());

          const lastItemId = data.users[data.users.length - 1].id;

          data.users.push({
            id: lastItemId + 1,
            email: email,
            password: password,
          });

          await fs.writeFile(userdbPath, JSON.stringify(data));
        } catch (error) {
          throw new Error("Error registering user");
        }

        const access_token = createToken({ email });

        return { access_token };
      },
    },
    login: {
      type: TokenType,
      args: {
        email: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
      },
      resolve: async (_, args) => {
        const { email, password } = args;

        if (!(await isAuthenticated({ email, password }))) {
          throw new Error("Incorrect email or password", {
            code: "INCORRECT_CREDENTIALS",
          });
        }

        const access_token = createToken({ email });

        return { access_token };
      },
    },
  },
});

const schema = new GraphQLSchema({
  query: RootQueryType,
  mutation: RootMutationType,
});

app.use(cors());

//auth middleware
app.use(async (req, res, next) => {
  if (req.method === "OPTIONS") {
    next();
  }

  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    req.user = null;
    return next();
  }

  const token = authorizationHeader.replace("Bearer ", "");

  if (!token) {
    req.user = null;
    next();
  }

  try {
    const decoded = verifyToken(token);
    if (decoded instanceof Error) {
      req.user = null;
      next();
    } else {
      req.user = { ...decoded, token };
      next();
    }
  } catch (err) {
    req.user = null;
    next();
  }
});

app.use(
  "/graphql",
  graphqlHTTP((req) => ({
    schema,
    context: { req },
  }))
);

app.listen(PORT, () => {
  console.log(`GraphQL server is running at http://localhost:${PORT}/graphql`);
});
