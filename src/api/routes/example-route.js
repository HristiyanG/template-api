const exampleController = require('../controllers/example-controller');
const ErrorHandlers = require('../middlewares/error-handler');


/**
 * In a certain router class we could have as many routes as we want for the specific scenario
 */
class ExampleRouter {

    /**
     * Attaches new Methods Route to /methods
     * @param expressApp
     * @returns {router}
     */
    static route (expressApp) {
        let router = expressApp.Router();

        /**
         * Example of get request to the server path `/`
         */
        router.get('/', ErrorHandlers.globalErrorHandler(exampleController.emptyRouter));

        /**
         * Example of post request to the server path `/example`
         */
        router.post('/examples', ErrorHandlers.globalErrorHandler(exampleController.exampleRouter));

        /**
        * Example of get request to the server followed by an ID specified outside by parameter `/example/:id`
        */
        router.get('/examples/:id', ErrorHandlers.globalErrorHandler(exampleController.exampleRouterParam));

        return router;
    }
}

module.exports = ExampleRouter;
