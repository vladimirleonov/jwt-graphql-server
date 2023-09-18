const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const bodyParser = require("body-parser");
const cors = require("cors");
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLNonNull,
} = require("graphql");
const jwt = require("jsonwebtoken");
const fs = require("fs/promises");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(
  cors({
    origin: "*",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders: "Content-Type, Authorization",
  })
);

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
    dummy: { type: GraphQLString },
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

        const access_token = createToken({ email, password });

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
          throw new Error("Incorrect email or password");
        }

        const access_token = createToken({ email, password });

        return { access_token };
      },
    },
  },
});

const authMiddleware = (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }

  try {
    const token = req.headers.authorization.split(" ")[1];
    const verifyTokenResult = verifyToken(token);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = "Access token not provided";
      res.status(status).json({ status, message });
      return;
    }

    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
};

const schema = new GraphQLSchema({
  query: RootQueryType,
  mutation: RootMutationType,
});

app.use(
  "/graphql",
  graphqlHTTP({
    schema,
  })
);

app.listen(PORT, () => {
  console.log(`GraphQL server is running at http://localhost:${PORT}/graphql`);
});
