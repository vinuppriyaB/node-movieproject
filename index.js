// const movies = [
//   {
//     id: "100",
//     name: "Ratatouille",
//     pic: "https://images-na.ssl-images-amazon.com/images/S/pv-target-images/2b18044415b238c004e702aaf1dc693daf886d9dadf4b78e1b1bcc0b9df10f8c._RI_V_TTW_.jpg",
//     summary:
//       "Remy dreams of becoming a great chef, despite being a rat in a definitely rodent-phobic profession. He moves to Paris to follow his dream, and with the help of hapless garbage boy Linguini he puts his culinary skills to the test in the kitchen but he has to stay in hiding at the same time, with hilarious consequences. Remy eventually gets the chance to prove his culinary abilities to a great food critic but is the food good? A Pixar animation.",
//     rating: "8",
//     trailer: "https://www.youtube.com/embed/NgsQ8mVkN8w",
//     language: "english",
//   },
//   {
//     id: "101",
//     name: "Alita:Battle Angle",
//     pic: "https://proseandcomiccons.files.wordpress.com/2019/02/slick-new-poster-for-alita-battle-angel1.jpg?w=640",
//     summary:
//       "Set several centuries in the future, the abandoned Alita is found in the scrapyard of Iron City by Ido, a compassionate cyber-doctor who takes the unconscious cyborg Alita to his clinic. When Alita awakens, she has no memory of who she is, nor does she have any recognition of the world she finds herself in. As Alita learns to navigate her new life and the treacherous streets of Iron City, Ido tries to shield her from her mysterious past.",
//     rating: "7.7",
//     trailer: "https://www.youtube.com/embed/cislZ9S0ocA",
//     language: "english",
//   },

//   {
//     id: "102",
//     name: "City Hunter",
//     pic: "https://static.xemovie.com/images/Film/Series/City%20hunter.jpg",
//     summary:
//       "In 1983, the South Korean president and his delegates are visiting Burma when a bomb planted by North Korean agents explodes, killing some high-ranking officials. This historical event is called the Rangoon bombing (also known as the Rangoon incident).",
//     rating: "8.1",
//     trailer: "https://www.youtube.com/embed/YGr706kT7SM",
//     language: "korean",
//   },
//   {
//     id: "103",
//     name: " Interstellar",
//     pic: "https://m.media-amazon.com/images/I/A1JVqNMI7UL._SL1500_.jpg",

//     summary:
//       "In Earth's future, a global crop blight and second Dust Bowl are slowly rendering the planet uninhabitable. Professor Brand (Michael Caine), a brilliant NASA physicist, is working on plans to save mankind by transporting Earth's population to a new home via a wormhole. But first, Brand must send former NASA pilot Cooper (Matthew McConaughey) and a team of researchers through the wormhole and across the galaxy to find out which of three planets could be mankind's new home.",
//     rating: "8.7",
//     trailer: "https://www.youtube.com/embed/zSWdZVtXT7E",
//     language: "english",
//   },
// ];
// const express =require("express");
import express from "express";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";

import { movieRouter } from "./routes/movie.js";
import { userRouter } from "./routes/user.js";


dotenv.config();



const app = express();
const PORT = process.env.PORT || 9000;
const MONGO_URL = process.env.MONGO_URL;
// mongodb+srv://vinuppriya:<password>@cluster0.xu3bs.mongodb.net/myFirstDatabase?retryWrites=true&w=majority
app.use(express.json());
app.use(cors());

export async function createConnection() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  console.log("Mongodb connected");
  
  return client;
}

export const client = await createConnection();



app.get("/", (request, response) => {
  response.send("welcome");
});

app.use("/movies",movieRouter);
app.use("/user",userRouter);
  

app.listen(PORT, () => console.log("the server is started in", PORT));




// async function getMovieById(id) {
//     const client = await createConnection();
//     const movie = await client
//         .db("B27rwd")
//         .collection("movies")
//         .findOne({ id: id });
//     console.log(movie);
//     return movie;
// }







//   console.log(movie);
  //    const result= movies.find((mvn)=> mvn.id===id);
  //     result? response.send(result):response.send({message:"no match found"});
  // response.send(result|| {message:"no match movie"})



   //    const result= movies.find((mvn)=> mvn.id===id);
  //     result? response.send(result):response.send({message:"no match found"});
  // response.send(result|| {message:"no match movie"})

//   app.get("/movies", async(request, response) => {
//     console.log(request.query);
//     let filter =request.query;
  // if(filter.rating)
  // {
  //     filter.rating=parseInt(filter.rating);
  // }
    // const client = await createConnection();
    // const movie = await client
    //   .db("B27rwd")
    //   .collection("movies")
    //   .find(filter)
    //   .toArray();
  //   const { language, rating } = request.query;
  //   let filtermovie = movies;
  
  //   if (language) {
  //     filtermovie = filtermovie.filter((mvn) => mvn.language === language);
  //   }
  //   if (rating) {
  //     filtermovie = filtermovie.filter((mvn) => mvn.rating === rating);
  //   }
  
//     response.send(movie);
//   });
  