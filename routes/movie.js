import express from "express";
// import {client} from "../index.js";

import { 
    getMovieById,
    createMovie,
    editMovieByName,
    deleteAllMovie,
    deleteMovieByID,
    getMovieByfilter
 } 
 from "../helper.js";
import { auth } from "../middleware/auth.js"
  const router= express.Router();

router
.route("/")
.get( async(request, response) => {
    console.log(request.query);
    let filter =request.query;
    const movie = await getMovieByfilter(filter);
    response.send(movie);
  })
.post( async (request, response) => {
    const data = request.body;
    console.log(data)
    const movie = await createMovie(data);
  
    response.send(movie);
  })
.put( async (request, response) => {
    const {id} = request.query;
    const movie = await editMovieByName(id, request);
    response.send(movie);
    // const result = await client
    //   .db("B27rwd")
    //   .collection("movies")
    //   .findOne({ name:name});
    //   response.send(result)
  })
.delete( async(request, response) => {
    console.log(request.query);
    let filter =request.query;
    const movie = await deleteAllMovie(filter);
    response.send(movie);
  });  
  
 router 
 .route("/:id")
  .get( async (request, response) => {
    const { id } = request.params;
    const movie = await getMovieById(id);
   
    response.send(movie);
  })
  .delete(async (request, response) => {
    const { id } = request.params;
    const movie = await deleteMovieByID(id);
    response.send(movie);
  })
  .put( async (request, response) => {
    const {id} = request.params;
    const movie = await editMovieByName(id, request);
    response.send(movie);
    // const result = await client
    //   .db("B27rwd")
    //   .collection("movies")
    //   .findOne({ name:name});
    //   response.send(result)
  }) 
   
  
  
  
    export const movieRouter=router;
  
  //  sample code
    // router.delete("/movies/:id", async (request, response) => {
    //   const { id } = request.params;
    //   const movie = await deleteMovieByID(id);
    //   response.send(movie);
    //   });  
     