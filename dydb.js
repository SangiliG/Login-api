const { DynamoDB } = require('aws-sdk');
const AWS= require('aws-sdk');
const express=require("express");
require('dotenv').config();
const router=express.Router();

AWS.config.update({
    region:process.env.AWS_DEFAULT_REGION,
    accessKeyId:process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY
});

const dynamoClient=new AWS.DynamoDB.DocumentClient();
const Table_Name="login-module";
console.log("Connected Successfully");
console.log("-------------------------");

router.post('/',async(req,res)=>{
    const param={
        TableName:Table_Name,
        Items:req.body
    }
    await dynamoClient.put(param).promise().then(()=>{
        const body={
            Operation:'SAVE',
            Message:'SUCCESS',
            Item:req.body
        }
        res.json(body);
    },error=>{
        console.error('error occured',error);
    })
})

