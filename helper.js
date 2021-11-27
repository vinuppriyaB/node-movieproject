import {createConnection} from "./index.js";
import {client} from "./index.js";
import bcrypt from "bcrypt";
import { ObjectId } from "mongodb";

// genPassword("password@123");

 async function getMovieById(id) {
    // const client = await createConnection();
    const result = await client
        .db("B27rwd")
        .collection("movies")
        .findOne({ _id: objectId(id)});
    return result;
}

async function getMovieByfilter(filter) {
    const client = await createConnection();
    const movie = await client
        .db("B27rwd")
        .collection("movies")
        .find(filter)
        .toArray();
    return movie;
}



async function createMovie(data) {
    // const client = await createConnection();
    console.log("data "+data);
    const movie = await client
        .db("B27rwd")
        .collection("movies")
        .insertOne(data);
    console.log(movie);
    return movie;
}



async function editMovieByName(id, request) {
    // const client = await createConnection();
    const movie = await client
        .db("B27rwd")
        .collection("movies")
        .updateOne({ id:id }, { $set: request.body });
    console.log(movie);
    return movie;
}

async function deleteAllMovie(filter) {
    // const client = await createConnection();
    const movie = await client
        .db("B27rwd")
        .collection("movies")
        .delete(filter);
    return movie;
}

async function deleteMovieByID(id) {
    // const client = await createConnection();
    const movie = await client
        .db("B27rwd")
        .collection("movies")
        .deleteOne({ id: id });
    console.log(movie);
    return movie;
}

async function genPassword(password)
{
  const salt = await bcrypt.genSalt(10);
  
  const hashedPassword= await bcrypt.hash(password,salt);
    return hashedPassword;
}
async function createUser(username,password) {
   
//    console.log(username,password)
    const user = await client
        .db("B27rwd")
        .collection("login")
        .insertMany([{username:username,password:password}]);
    console.log(user);
    return user;
}
async function checkAvailUser(username){
    const user = await client
        .db("B27rwd")
        .collection("login")
        .findOne({"username":username});
    console.log(user);
    return user;

}

export{
    getMovieById,
    getMovieByfilter,
    createMovie,
    editMovieByName,
    deleteAllMovie,
    deleteMovieByID,
    genPassword,
    createUser,
    checkAvailUser

};