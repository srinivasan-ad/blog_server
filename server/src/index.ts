import express from 'express';
import cors from 'cors'
import dotenv from 'dotenv'; 
dotenv.config();
import {Pool} from 'pg'
const app : express.Application = express();
app.use(cors());
app.use(express.json());
const pool = new Pool({connectionString : process.env.DATABASE_URL})
async function connectDB() {
    const client = await pool.connect()
    try {
      console.log("Connected to database")
      return client
    } catch (error) {
      console.error("Database connection failed", error)

    }
  }

  const client = pool.connect()
  .then(client => {
      console.log("Connected to database");
      client.release();
  })
  .catch(err => console.error("Database connection failed", err));

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
        
            const insertQuery = 'INSERT INTO Users(name, username, password) VALUES($1, $2, $3) ON CONFLICT(username) DO NOTHING  RETURNING * ;';
            const insertQueryResult = await pool.query(insertQuery, [name, username, password]);
            if(insertQueryResult.rowCount === 0)
            {
                console.log('Query insertion failed !');
              return res.status(400).json({success : false , exist : false , mssg  : 'Insertion failed' } )
            }
        return res.status(200).json({success : true , exist : false , mssg : 'Info inserted successfully'})
        
    }
       
    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});
app.post('/user/signin', async(req,res) : Promise<any>  =>  {
    const{username,password} = req.body 
    try{
        const selectQuery = 'SELECT * FROM Users WHERE username = $1 ;'
        const selectQueryResult = await pool.query(selectQuery , [username])
        if(selectQueryResult.rows.length === 0)
        {
            return res.status(404).json({mssg : 'Username is incorrect'})
        }
        else if(password != selectQueryResult.rows[0].password)
        {
            return res.status(405).json({mssg : 'Password is incorrect'}) 
        }
        else
        {
            return res.status(201).json({mssg : 'Login is successful'})  
        }
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