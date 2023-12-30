import express from 'express'

const app = express()

app.use('/', (request, response) => {
    console.log('Hello');

    response.send("Hello, class")

});

app.listen(3000, () => {
    console.log ('Server listening')
})