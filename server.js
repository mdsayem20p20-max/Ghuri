const express=require("express");
const path=require("path"), jwt=require("jsonwebtoken"), bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const app=express(), db=new Database("ghuri.db");
const PORT=process.env.PORT||3000, SECRET=process.env.JWT_SECRET||"ghuri-change-this-secret";

app.use(express.json({limit:"5mb"})); app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT DEFAULT 'customer',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT NOT NULL,price REAL NOT NULL,old_price REAL,emoji TEXT DEFAULT '🛍️',image TEXT DEFAULT '',stock INTEGER DEFAULT 0,description TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,payment TEXT NOT NULL,total REAL NOT NULL,status TEXT DEFAULT 'Pending',items TEXT NOT NULL,transaction_id TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`);
const defaults={
 logo:"Ghuri", hotline:"01945900828", bkash:"01945900828", nagad:"01945900828",
 cover_title:"Everything you need. One simple place.",
 cover_text:"Shop electronics, fashion, home, beauty and more with bKash, Nagad and Cash on Delivery.",
 cover_image:"", offer_text:"Special Offers • Fast Delivery • Easy Checkout"
};
const set=db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)");
Object.entries(defaults).forEach(([k,v])=>set.run(k,v));

const adminEmail="admin@ghuri.com";
if(!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail))
  db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)").run("Ghuri Admin",adminEmail,bcrypt.hashSync("Admin@123",10),"admin");

if(!db.prepare("SELECT id FROM products LIMIT 1").get()){
  const p=db.prepare("INSERT INTO products(name,category,price,old_price,emoji,image,stock,description) VALUES(?,?,?,?,?,?,?,?)");
  [
   ["Wireless Headphones","Electronics",1890,2490,"🎧","",25,"Comfortable wireless headphones with rich sound."],
   ["Smart Watch Pro","Electronics",2990,3990,"⌚","",18,"Smart watch for everyday fitness and notifications."],
   ["Premium Backpack","Lifestyle",1450,1890,"🎒","",30,"Durable everyday backpack with laptop compartment."],
   ["Running Sneakers","Fashion",2250,2990,"👟","",16,"Lightweight sneakers for daily running and walking."],
   ["Cotton T-Shirt","Fashion",690,890,"👕","",45,"Soft premium cotton casual T-shirt."],
   ["Modern Table Lamp","Home",980,1250,"💡","",20,"Minimal table lamp for bedroom or workspace."],
   ["Bluetooth Speaker","Electronics",1590,1990,"🔊","",22,"Portable speaker with clear sound and deep bass."],
   ["Skin Care Set","Beauty",1290,1690,"🧴","",14,"Everyday skin-care essentials in one set."]
  ].forEach(x=>p.run(...x));
}

const auth=(req,res,next)=>{try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.user=jwt.verify(h.slice(7),SECRET);next()}catch(e){res.status(401).json({error:"Unauthorized"})}};
const optionalAuth=(req,res,next)=>{try{const h=req.headers.authorization||"";req.user=h.startsWith("Bearer ")?jwt.verify(h.slice(7),SECRET):null}catch(e){req.user=null}next()};
const admin=(req,res,next)=>{if(req.user?.role!=="admin")return res.status(403).json({error:"Admin only"});next()};

app.get("/api/settings",(req,res)=>{const rows=db.prepare("SELECT key,value FROM settings").all();res.json(Object.fromEntries(rows.map(x=>[x.key,x.value])))});
app.patch("/api/admin/settings",auth,admin,(req,res)=>{
  const allowed=Object.keys(defaults);
  const q=db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  const tx=db.transaction(()=>Object.entries(req.body).filter(([k])=>allowed.includes(k)).forEach(([k,v])=>q.run(k,String(v??"")))); tx(); res.json({ok:true});
});

app.get("/api/products",(req,res)=>{
  const q=(req.query.q||"").trim();
  const rows=q?db.prepare("SELECT * FROM products WHERE name LIKE ? OR category LIKE ? ORDER BY id DESC").all(`%${q}%`,`%${q}%`):db.prepare("SELECT * FROM products ORDER BY id DESC").all();
  res.json(rows)
});
app.post("/api/register",(req,res)=>{try{const {name,email,password}=req.body;if(!name||!email||!password)return res.status(400).json({error:"All fields required"});const hash=bcrypt.hashSync(password,10);const r=db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").run(name,email,hash);const token=jwt.sign({id:r.lastInsertRowid,name,email,role:"customer"},SECRET,{expiresIn:"7d"});res.json({token,user:{name,email,role:"customer"}})}catch(e){res.status(400).json({error:"Email already exists"})}});
app.post("/api/login",(req,res)=>{const u=db.prepare("SELECT * FROM users WHERE email=?").get(req.body.email);if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:"Invalid email or password"});const token=jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role},SECRET,{expiresIn:"7d"});res.json({token,user:{name:u.name,email:u.email,role:u.role}})});
app.get("/api/me",auth,(req,res)=>res.json(req.user));

app.post("/api/orders",optionalAuth,(req,res)=>{
 const {name,phone,address,payment,items,transaction_id=""}=req.body;
 if(!name||!phone||!address||!payment||!Array.isArray(items)||!items.length)return res.status(400).json({error:"Missing order information"});
 if(["bKash","Nagad"].includes(payment)&&!transaction_id.trim())return res.status(400).json({error:"Please enter your transaction ID"});
 let total=0,clean=[];const get=db.prepare("SELECT * FROM products WHERE id=?");const update=db.prepare("UPDATE products SET stock=stock-? WHERE id=?");
 for(const i of items){const p=get.get(i.id),qty=Math.max(1,Number(i.qty)||1);if(!p||p.stock<qty)return res.status(400).json({error:`Insufficient stock for ${p?.name||"product"}`});total+=p.price*qty;clean.push({id:p.id,name:p.name,price:p.price,qty,emoji:p.emoji});}
 const tx=db.transaction(()=>{for(const i of clean)update.run(i.qty,i.id);return db.prepare("INSERT INTO orders(user_id,name,phone,address,payment,total,items,transaction_id) VALUES(?,?,?,?,?,?,?,?)").run(req.user?.id||null,name,phone,address,payment,total,JSON.stringify(clean),transaction_id.trim())});
 const r=tx();res.json({id:r.lastInsertRowid,total,status:"Pending"});
});
app.get("/api/my-orders",auth,(req,res)=>res.json(db.prepare("SELECT id,total,payment,status,created_at,items,transaction_id FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id).map(o=>({...o,items:JSON.parse(o.items)}))));

app.get("/api/admin/stats",auth,admin,(req,res)=>{
 const products=db.prepare("SELECT COUNT(*) c FROM products").get().c,orders=db.prepare("SELECT COUNT(*) c FROM orders").get().c;
 const revenue=db.prepare("SELECT COALESCE(SUM(total),0) v FROM orders WHERE status!='Cancelled'").get().v;
 const customers=db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c;res.json({products,orders,revenue,customers});
});
app.get("/api/admin/orders",auth,admin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all().map(o=>({...o,items:JSON.parse(o.items)}))));
app.post("/api/admin/products",auth,admin,(req,res)=>{
 const {name,category,price,old_price,emoji,image,stock,description}=req.body;
 if(!name||!category||Number(price)<=0)return res.status(400).json({error:"Name, category and price required"});
 const r=db.prepare("INSERT INTO products(name,category,price,old_price,emoji,image,stock,description) VALUES(?,?,?,?,?,?,?,?)").run(name,category,Number(price),old_price?Number(old_price):null,emoji||"🛍️",image||"",Number(stock)||0,description||"");res.json({id:r.lastInsertRowid});
});
app.patch("/api/admin/products/:id",auth,admin,(req,res)=>{
 const p=db.prepare("SELECT * FROM products WHERE id=?").get(req.params.id);if(!p)return res.status(404).json({error:"Not found"});
 const x={...p,...req.body};db.prepare("UPDATE products SET name=?,category=?,price=?,old_price=?,emoji=?,image=?,stock=?,description=? WHERE id=?").run(x.name,x.category,Number(x.price),x.old_price?Number(x.old_price):null,x.emoji||"🛍️",x.image||"",Number(x.stock)||0,x.description||"",p.id);res.json({ok:true});
});
app.delete("/api/admin/products/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM products WHERE id=?").run(req.params.id);res.json({ok:true})});
app.patch("/api/admin/orders/:id",auth,admin,(req,res)=>{const allowed=["Pending","Confirmed","Processing","Shipped","Delivered","Cancelled"];if(!allowed.includes(req.body.status))return res.status(400).json({error:"Invalid status"});db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true})});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Ghuri running on http://localhost:${PORT}`));
