function checkAuthentication(req,res,next){
    if(req.isAuthenticated() === false){
      return req.redirect("/login");
    }
    next();
  }