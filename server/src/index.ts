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
  async function CheckTokenValidity(req: any, res: any, next: any): Promise<any> {
    const token = req.cookies?.authToken;

    if (!token) {
        return res.status(401).json({ isValid: false, mssg: "No token provided!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as jwt.JwtPayload & { username: string };

        const selectQuery = 'SELECT * FROM Users WHERE username = $1;';
        const result = await pool.query(selectQuery, [decoded.username]);

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, mssg: "Invalid token!" });
        }

        return next(); 
    } catch (e) {
        console.error("JWT Error:", e);
        return res.status(401).json({ isValid: false, mssg: "Token expired or invalid!" });
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

app.get('/user/validate', async (req, res) : Promise<any> => {
    const token = req.cookies?.authToken;

    if (!token) {
        return res.status(401).json({ isValid: false, message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as jwt.JwtPayload & { username: string };
        const result = await pool.query('SELECT * FROM Users WHERE username = $1;', [decoded.username]);

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, message: "Invalid token" });
        }

        return res.status(200).json({ isValid: true, user: result.rows[0] });
    } catch (error) {
        return res.status(401).json({ isValid: false, message: "Token expired or invalid" });
    }
});

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
            let token = jwt.sign({ username: username }, process.env.JWT_SECRET_KEY as string , { expiresIn: "2m" });
            res.cookie("authToken", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', 
                maxAge:  2 * 60 * 1000
            });
        return res.status(200).json({success : true , exist : false , mssg : 'Info inserted successfully'})
        
    }
       
    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});
app.post('/user/signin',async(req,res) : Promise<any>  =>  {
    const{username,password} = req.body 
    
    try{
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
        const newToken = jwt.sign({ username: username }, process.env.JWT_SECRET_KEY as string , { expiresIn: "2m" });
        res.cookie("authToken", newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            maxAge:  2 * 60 * 1000
        });
        return res.status(200).json({mssg : 'Logged in successfully'})
    }
    catch(e)
    {
        console.error(e)
        return res.status(500).json({mssg : "Internal Server Error" });
    }
})
app.post('/user/blog' , CheckTokenValidity , (req,res) : Promise<any> => {
    
})
app.put('/user/blog' , CheckTokenValidity, (req,res) => {
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