require('dotenv').config();
const express = require('express');

const exampleRouter = require('./src/api/routes/example-route');
const exampleErrorRouter = require('./src/api/routes/example-error-route');
const ErrorHandler = require('./src/api/middlewares/error-handler');
const ExampleMiddleware = require('./src/api/middlewares/example-mdw');

const app = express();
app.use(express.json());

app.use('/', ExampleMiddleware.exampleValidation, exampleRouter.route(express));
app.use('/errors', exampleErrorRouter.route(express));

// Attach API Error handler
app.use(ErrorHandler.apiErrorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.info(`App listening on: ` + PORT);
});