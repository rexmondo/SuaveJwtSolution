open Encodings
open Secure
open Suave.Web
open Suave.Http
open Suave.Successful
open Suave.Filters
open Suave.Operators

[<EntryPoint>]
let main argv = 
    let base64Key = 
        Base64String.fromString "QXb5FySta_ou8-sK8lN255i0edS75--w8kVfiEGW3IQ"
    let jwtConfig = {
        Issuer = "http://localhost:8083/suave"
        ClientId = "c2ac9ade741744eebbed3c5ac3cd66fc"
        SecurityKey = KeyStore.securityKey base64Key
    }

    let sample1 =
        path "/audience/sample1"
        >=> jwtAuthenticate jwtConfig (OK "Sample 1")
    let config =
        { defaultConfig 
            with bindings = [HttpBinding.mkSimple HTTP "127.0.0.1" 8084]}
    startWebServer config sample1
    0