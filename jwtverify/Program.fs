// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

open Suave
open Suave.Filters
open Suave.Operators
open System
open System.Threading
open System.Security.Cryptography
open Newtonsoft


/// Logic Part

let unixTimestamp () =
    DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).Ticks / TimeSpan.TicksPerSecond

let endpointOfConfiguration op = op + "/.well-known/openid-configuration"

let httpGet (url : string) =
    new System.Net.WebClient()
    |> (fun c -> c.DownloadData url)
    |> System.Text.Encoding.UTF8.GetString

let toJson = Json.Linq.JObject.Parse

type KeyAlg =
    | RSA of RSACryptoServiceProvider

type Key =
    | Key of string * string * KeyAlg

exception ValidationError of string

let decodeBase64Url (s : string) =
    s.Replace('-', '+').Replace('_', '/')
    |> fun x -> x.PadRight(x.Length + (4 - x.Length % 4) % 4, '=')
    |> System.Convert.FromBase64String

let stringValue key (obj : Json.Linq.JToken) : string =
    Json.Linq.JToken.op_Explicit obj.[key]

let intValue key (obj : Json.Linq.JToken) : int64 =
    Json.Linq.JToken.op_Explicit obj.[key]

let intValueTry key (obj : Json.Linq.JToken) : int64 option =
    try       Some (intValue key obj)
    with _ -> None

let objectToKey obj =
    match stringValue "kty" obj, stringValue "alg" obj, stringValue "kid" obj with
    | "RSA", alg, kid ->
        let mutable ps = new RSAParameters()
        ps.Modulus  <- stringValue "n" obj |> decodeBase64Url
        ps.Exponent <- stringValue "e" obj |> decodeBase64Url
        let csp = new RSACryptoServiceProvider()
        csp.ImportParameters(ps)
        Some (Key (kid, alg, RSA csp))
    | _ -> None

let getIssuerJwks iss =
    iss
    |> endpointOfConfiguration
    |> httpGet |> toJson
    |> stringValue "jwks_uri"
    |> httpGet |> toJson
    |> (fun o -> o.["keys"].Children())
    |> Seq.map objectToKey
    |> Seq.choose id

let verifyWithKeys kid alg keys tkn =
    let key = keys |> Seq.find (fun (Key (i, a, _)) -> i = kid && a = alg)
    match alg, key with
    | "RS256", Key (_, _, RSA key) ->
        let payload = Jose.JWT.Decode(tkn, key, Jose.JwsAlgorithm.RS256)
        sprintf """{"claims":%O,"valid":true,"error":null}""" payload
    | _ ->
        raise (ValidationError "unsupported alg")

let verifyJwt itkn =
    let errormsg msg =
        sprintf """{"claims":null,"valid":false,"error":"%s"}""" msg
    try
        let header  = itkn |> Jose.JWT.Headers
        let payload = itkn |> Jose.JWT.Payload |> toJson
        let alg = header.["alg"] :?> string
        let kid = header.["kid"] :?> string
        let iss = stringValue "iss" payload
        let exp = intValueTry "exp" payload
        match exp with
        | Some n ->
            if n < unixTimestamp()
            then raise (ValidationError "exp")
            else
                let keys = getIssuerJwks iss
                verifyWithKeys kid alg keys itkn
        | None ->
                let keys = getIssuerJwks iss
                verifyWithKeys kid alg keys itkn
    with
    | ValidationError e -> errormsg e
    | _                 -> errormsg "error"


/// Server Part

let applyParam name f = fun x ->
    match x.request.queryParam name with
    | Choice1Of2 c when not (String.IsNullOrWhiteSpace c) -> f c x
    | _ -> match x.request.formData name with
           | Choice1Of2 c when not (String.IsNullOrWhiteSpace c) -> f c x
           | _ -> fail

let app =
    choose [
        path "/tokeninfo"
        >=> choose [ GET; POST ]
        >=> applyParam "id_token" (fun a ->
            verifyJwt a
            |> Successful.OK);
        RequestErrors.BAD_REQUEST ""
    ]
    >=> Writers.setMimeType "application/json; charset=utf-8"

[<EntryPoint>]
let main argv =
    startWebServer defaultConfig app
    0 // return an integer exit code
