import express, { NextFunction } from 'express';
import cors from 'cors'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv'; 
dotenv.config();
import {Pool} from 'pg'
const app : express.Application = express();
app.use(cookieParser())
app.use(cors());
app.use(express.json());
const pool = new Pool({connectionString : process.env.DATABASE_URL})
  const client = pool.connect()
  .then(client => {
      console.log("Connected to database");
      client.release();
  })
  .catch(err => console.error("Database connection failed", err));

async function CheckTokenValidity(req : any ,res : any ,next : any) : Promise<any>
{
const token =   req.cookies?.authToken;
try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string);
    const selectQuery = 'SELECT * FROM Users WHERE username = $1;'
    const result = await pool.query(selectQuery,[decoded]);
    if(result.rows.length === 0)
    {
        return res.status(404).json({isValid : false , mssg : "token has expired !"})
    }
    next();
    return res.status(202).json({isValid : true , mssg : "token is valid !"})

}
catch(e)
{
    console.error(e);
    return res.status(500).json({mssg : "Internal Server Error"})
}
}

app.get('/hello'  , (req,res) => {
    try{
         res.send("Hello champ !")
    }
    catch(e)
    {
        console.error(e);
    }
})

app.post('/user/signup', async (req , res ) : Promise<any> => {

const {name,username,password} = req.body

    try {
        const selectQuery = `Select * FROM Users WHERE username = $1 ;`;
        const selectResult = await pool.query(selectQuery,[username]);
        if(selectResult.rows.length > 0)
        {
            return res.status(400).json({ success : false , exist : true , mssg : 'Username is used'});
        }
        else{
            const saltRounds = 10; 
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const insertQuery = 'INSERT INTO Users(name, username, password) VALUES($1, $2, $3) ON CONFLICT(username) DO NOTHING  RETURNING * ;';
            const insertQueryResult = await pool.query(insertQuery, [name, username, hashedPassword]);
            if(insertQueryResult.rowCount === 0)
            {
                console.log('Query insertion failed !');
              return res.status(401).json({success : false , exist : false , mssg  : 'Insertion failed' } )
            }
            let token = jwt.sign({ username: username }, process.env.JWT_SECRET_KEY as string);
        return res.status(200).json({success : true , exist : false , mssg : 'Info inserted successfully'}).cookie("authToken", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            maxAge: 3 * 24 * 60 * 60 * 1000
        });
        
    }
       
    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});
app.post('/user/signin',async(req,res) : Promise<any>  =>  {
    const{username,password} = req.body 
    const token =   req.cookies?.authToken;
    try{
        if(token)
            {
                const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as jwt.JwtPayload & { username: string };;
                const tokenSelectQuery = 'SELECT * FROM Users WHERE username = $1;'
                const result = await pool.query(tokenSelectQuery,[decoded.username]);
                if(result.rows.length > 0)
                {
                    return res.status(210).json({isValid : true , mssg : "token is valid !"})
                }
            
            }
        const selectQuery = 'SELECT * FROM Users WHERE username = $1 ;'
        const selectQueryResult = await pool.query(selectQuery , [username])
        if(selectQueryResult.rows.length === 0)
        {
            return res.status(404).json({mssg : 'Username is incorrect'})
        }
        const hashedPassword = selectQueryResult.rows[0].password;
        const isValidPass = await bcrypt.compare(password, hashedPassword);
        if(!isValidPass)
        {
            return res.status(405).json({mssg : 'Password is incorrect'}) 
        }
        const newToken = jwt.sign({ username: username }, process.env.JWT_SECRET_KEY as string);
        return res.status(200).json({mssg : 'Logged in successfully'}).cookie("authToken", newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            maxAge: 3 * 24 * 60 * 60 * 1000
        });
    }
    catch(e)
    {
        console.error(e)
        return res.status(500).json({mssg : "Internal Server Error" });
    }
})

app.put('/user/blog' , (req,res) => {
    try{
          res.send("Blog entry route")
    }
    catch(e)
    {
        console.error(e);
    }
})

app.get('/user/blog' , (req,res) => {
    try{
         res.send("All blog get route")
    }
    catch(e)
    {
        console.error(e)
    }
})

app.get('/user/blog/getblog' , (req,res) => {
    try
    {
         res.send("Specific blog get route")
    }
    catch(e)
    {
        console.error(e)
    }
})
app.listen(process.env.PORT,() => 
{
    console.log(`Server ntarted at http://localhost:${process.env.PORT}`);
})