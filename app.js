const express=require("express");
const AWS= require('aws-sdk');
const path=require("path");
const bodyparser=require('body-parser')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const JSONWTKEY ='abc123'
const app=express();
 require("./dydb");

const port=process.env.PORT||5000;
app.listen(port,()=>{
    console.log("Listening on port: "+ port);
})
const static_path=path.join(__dirname,"./main");
app.use(express.static(static_path));
app.use(bodyparser.json())

//aws
AWS.config.update({
    region:process.env.AWS_DEFAULT_REGION,
    accessKeyId:process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY
});

const dynamoClient=new AWS.DynamoDB.DocumentClient();
const Table_Name="login-module";

//signup with role
app.post('/api/register',async(req,res)=>{
    const{email,password:plaintext,role}=req.body
    
    //email
    let emailTest=/^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
    if(!emailTest.test(email)){
        res.json({
            error:'invalid email'
        })
        return;
    }
    req.body.email=email
    //password
    let password = req.body.password
    let pwformat = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{6,16}$/;
    if(!pwformat.test(password))
    {
        res.json({
            error:"Password should be Valid"
        })
        return;
    }    

    let EPwd= await bcrypt.hash(plaintext,5);
    req.body.password=EPwd;
    //role
    req.body.role = role;       
    console.log("-------------------------");
    console.log("email:",email);
    console.log( "password:",password);
    console.log("role:",role);
    
    res.json({status:'OK'})
    //json
    const param={
        TableName:Table_Name,
        Item:req.body  
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
});

//login with role
app.post('/api/login',async(req,res)=>{
        let email=req.body.email;
        let password =req.body.password;
        let role=req.body.role;
        let parameter={
            TableName:Table_Name,
            KeyConditionExpression:"#email = :emailValue",
            ExpressionAttributeNames:{
                "#email":"email"
            },
            ExpressionAttributeValues:{
                ":emailValue":email
            },
        }

        dynamoClient.query(parameter, function(err,data){
            if(!err){
                let Epassword=data.Items[0].password
                let Arole=data.Items[0].role
                if(role==Arole){
                bcrypt.compare(password,Epassword).then(doMatch =>{
                    if(doMatch){
                        const token=jwt.sign({id:email,role:role},JSONWTKEY,
                            {
                            expiresIn: '10m'
                        })
                        console.log("Welcome "+Arole+" "+ email +"!")
                        console.log("Token : "+token)
                        res.json({
                            message:`Welcome ${Arole} ${email}!.. Keep your JWT token safe!`,
                            "Token": token,
                            "status":"OK",
                            role:Arole,
                            data:token
                        })
                    }
                    else{
                        res.send("Your credentials are wrong")
                        console.log("Given username and password are didn't match..");
                    }
                }).catch(err=>{
                    console.log("Internal Error with Decryption")
                    console.log(err);
                })  
            }else{
                res.json({
                    message:"Your role type is wrong",
                    "status":"Error"});
                console.log("Given role is invalid..");
            }
        } 
        })
     })

//changepassword
app.post('/api/changepwd',async(req,res)=>{
    const {token,newpassword:newplaintext}=req.body
    try{
            const user=jwt.verify(token,JSONWTKEY)
            const email=user.id
            const password=await bcrypt.hash(newplaintext,10)
            const params = {
            TableName: Table_Name,
            Key:{
                "email":email,
                },
                UpdateExpression: "set password =:password",
                ExpressionAttributeValues: {
                ":password": password
            },
            ReturnValues:"UPDATED_NEW"
            };

            console.log(email);
            console.log("--------------------------------");
            console.log(password);
            console.log("---------------------------------");
            console.log("Decoded",user);

            let updatedpwd=await dynamoClient.update(params).promise()
            console.log(updatedpwd.Attributes.password);

                if(updatedpwd.Attributes.password==password){
                res.json({status:"OK"})
                }else{
                console.log("Something error!")
                res.json({status:"Failed"})
                }
                }

                catch(err){
                    res.json({status:"Failed"})
                    console.log(err);
            }
        })


