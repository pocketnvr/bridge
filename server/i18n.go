package server

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	langEN = "en"
	langFR = "fr"
	langDE = "de"
	langES = "es"
	langIT = "it"
	langNL = "nl"
)

var languages = []string{langEN, langFR, langDE, langES, langIT, langNL}

func langOf(r *http.Request) string {
	best, bestQ := langEN, -1.0
	for i, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		q -= float64(i) * 1e-6
		base := strings.ToLower(strings.SplitN(strings.TrimSpace(tag), "-", 2)[0])
		if slices.Contains(languages, base) && q > bestQ {
			best, bestQ = base, q
		}
	}
	return best
}

func tr(lang, key string, args ...any) string {
	m, ok := messages[key]
	if !ok {
		return key
	}
	s, ok := m[lang]
	if !ok {
		s = m[langEN]
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

func decimalMark(lang, s string) string {
	if lang == langEN {
		return s
	}
	return strings.Replace(s, ".", ",", 1)
}

var messages = map[string]map[string]string{
	"err.lanOnly": {
		langEN: "This page is only available on the local network.",
		langFR: "Page réservée au réseau local.",
		langDE: "Diese Seite ist nur im lokalen Netzwerk verfügbar.",
		langES: "Esta página solo está disponible en la red local.",
		langIT: "Questa pagina è disponibile solo sulla rete locale.",
		langNL: "Deze pagina is alleen beschikbaar op het lokale netwerk.",
	},
	"err.host": {
		langEN: "Open this page with the server's IP address (or add this name to ALLOWED_HOSTS).",
		langFR: "Ouvrez cette page avec l'adresse IP du serveur (ou ajoutez ce nom à ALLOWED_HOSTS).",
		langDE: "Öffnen Sie diese Seite mit der IP-Adresse des Servers (oder fügen Sie diesen Namen zu ALLOWED_HOSTS hinzu).",
		langES: "Abra esta página con la dirección IP del servidor (o añada este nombre a ALLOWED_HOSTS).",
		langIT: "Apra questa pagina con l'indirizzo IP del server (o aggiunga questo nome ad ALLOWED_HOSTS).",
		langNL: "Open deze pagina met het IP-adres van de server (of voeg deze naam toe aan ALLOWED_HOSTS).",
	},
	"err.notLoggedIn": {langEN: "not signed in", langFR: "non connecté", langDE: "nicht angemeldet", langES: "sesión no iniciada", langIT: "accesso non effettuato", langNL: "niet ingelogd"},
	"err.badOrigin":   {langEN: "origin refused", langFR: "origine refusée", langDE: "Herkunft abgelehnt", langES: "origen rechazado", langIT: "origine rifiutata", langNL: "herkomst geweigerd"},
	"err.qrExpired": {
		langEN: "QR code expired: generate a new one.",
		langFR: "QR expiré : générez un nouveau QR.",
		langDE: "QR-Code abgelaufen: Erzeugen Sie einen neuen.",
		langES: "Código QR caducado: genere uno nuevo.",
		langIT: "Codice QR scaduto: ne generi uno nuovo.",
		langNL: "QR-code verlopen: maak een nieuwe aan.",
	},
	"err.fileExpired": {
		langEN: "File expired: generate a new QR code.",
		langFR: "Fichier expiré : générez un nouveau QR.",
		langDE: "Datei abgelaufen: Erzeugen Sie einen neuen QR-Code.",
		langES: "Archivo caducado: genere un nuevo código QR.",
		langIT: "File scaduto: generi un nuovo codice QR.",
		langNL: "Bestand verlopen: maak een nieuwe QR-code aan.",
	},
	"err.linkExpired": {
		langEN: "Link expired or already used.",
		langFR: "Lien expiré ou déjà utilisé.",
		langDE: "Link abgelaufen oder bereits verwendet.",
		langES: "Enlace caducado o ya utilizado.",
		langIT: "Link scaduto o già usato.",
		langNL: "Link verlopen of al gebruikt.",
	},
	"err.pwShort": {
		langEN: "At least 8 characters, and both entries must match.",
		langFR: "8 caractères minimum, et les deux saisies doivent être identiques.",
		langDE: "Mindestens 8 Zeichen, und beide Eingaben müssen übereinstimmen.",
		langES: "Mínimo 8 caracteres, y las dos entradas deben coincidir.",
		langIT: "Almeno 8 caratteri, e i due inserimenti devono coincidere.",
		langNL: "Minstens 8 tekens, en beide invoeren moeten overeenkomen.",
	},
	"err.pwLong": {langEN: "72 characters maximum.", langFR: "72 caractères maximum.", langDE: "Höchstens 72 Zeichen.", langES: "Máximo 72 caracteres.", langIT: "Massimo 72 caratteri.", langNL: "Maximaal 72 tekens."},
	"err.tooMany": {
		langEN: "Too many attempts. Try again in a few minutes.",
		langFR: "Trop d'essais. Réessayez dans quelques minutes.",
		langDE: "Zu viele Versuche. Versuchen Sie es in ein paar Minuten erneut.",
		langES: "Demasiados intentos. Vuelva a intentarlo dentro de unos minutos.",
		langIT: "Troppi tentativi. Riprovi tra qualche minuto.",
		langNL: "Te veel pogingen. Probeer het over een paar minuten opnieuw.",
	},
	"err.badPassword": {langEN: "Wrong password.", langFR: "Mot de passe incorrect.", langDE: "Falsches Passwort.", langES: "Contraseña incorrecta.", langIT: "Password errata.", langNL: "Onjuist wachtwoord."},
	"err.noPublic": {
		langEN: "Public address unknown: set PUBLIC_HOST.",
		langFR: "Adresse publique inconnue : renseignez PUBLIC_HOST.",
		langDE: "Öffentliche Adresse unbekannt: Setzen Sie PUBLIC_HOST.",
		langES: "Dirección pública desconocida: indique PUBLIC_HOST.",
		langIT: "Indirizzo pubblico sconosciuto: imposti PUBLIC_HOST.",
		langNL: "Openbaar adres onbekend: stel PUBLIC_HOST in.",
	},
	"err.noFreeAddr": {
		langEN: "No free address left for a new phone.",
		langFR: "Plus d'adresse libre pour un nouveau téléphone.",
		langDE: "Keine freie Adresse mehr für ein neues Telefon.",
		langES: "No queda ninguna dirección libre para un nuevo teléfono.",
		langIT: "Nessun indirizzo libero per un nuovo telefono.",
		langNL: "Geen vrij adres meer voor een nieuwe telefoon.",
	},
	"err.deleteFailed": {
		langEN: "Deletion incomplete, try again: %s",
		langFR: "Suppression incomplète, réessayez : %s",
		langDE: "Löschen unvollständig, versuchen Sie es erneut: %s",
		langES: "Eliminación incompleta, vuelva a intentarlo: %s",
		langIT: "Eliminazione incompleta, riprovi: %s",
		langNL: "Verwijderen onvolledig, probeer het opnieuw: %s",
	},
	"err.generic": {langEN: "Error: %s", langFR: "Erreur : %s", langDE: "Fehler: %s", langES: "Error: %s", langIT: "Errore: %s", langNL: "Fout: %s"},

	"warn.frigateDown": {
		langEN: "Frigate can't be reached from the Bridge (%s). Check FRIGATE_URL. With the Home Assistant Frigate add-on, enable port 8971 in its configuration (Network section).",
		langFR: "Frigate injoignable depuis le Bridge (%s). Vérifiez FRIGATE_URL. Avec le module Frigate de Home Assistant, activez le port 8971 dans sa configuration (section Réseau).",
		langDE: "Frigate ist von der Bridge aus nicht erreichbar (%s). Prüfen Sie FRIGATE_URL. Beim Frigate-Add-on von Home Assistant aktivieren Sie Port 8971 in dessen Konfiguration (Abschnitt Netzwerk).",
		langES: "Frigate no es accesible desde el Bridge (%s). Compruebe FRIGATE_URL. Con el complemento Frigate de Home Assistant, active el puerto 8971 en su configuración (sección Red).",
		langIT: "Frigate non è raggiungibile dal Bridge (%s). Verifichi FRIGATE_URL. Con il componente aggiuntivo Frigate di Home Assistant, attivi la porta 8971 nella sua configurazione (sezione Rete).",
		langNL: "Frigate is niet bereikbaar vanaf de Bridge (%s). Controleer FRIGATE_URL. Met de Frigate-add-on van Home Assistant: schakel poort 8971 in de configuratie ervan in (sectie Netwerk).",
	},
	"warn.port5000": {
		langEN: "FRIGATE_URL uses Frigate's port 5000, which has no authentication: every phone you add gets full admin access. Prefer port 8971 (https://IP:8971).",
		langFR: "FRIGATE_URL utilise le port 5000 de Frigate, qui n'a pas d'authentification : chaque téléphone ajouté a un accès administrateur complet. Préférez le port 8971 (https://IP:8971).",
		langDE: "FRIGATE_URL verwendet Port 5000 von Frigate, der keine Authentifizierung hat: Jedes hinzugefügte Telefon erhält vollen Administratorzugriff. Verwenden Sie lieber Port 8971 (https://IP:8971).",
		langES: "FRIGATE_URL usa el puerto 5000 de Frigate, que no tiene autenticación: cada teléfono añadido obtiene acceso completo de administrador. Mejor use el puerto 8971 (https://IP:8971).",
		langIT: "FRIGATE_URL usa la porta 5000 di Frigate, che non ha autenticazione: ogni telefono aggiunto ottiene un accesso completo da amministratore. Preferisca la porta 8971 (https://IP:8971).",
		langNL: "FRIGATE_URL gebruikt poort 5000 van Frigate, die geen authenticatie heeft: elke toegevoegde telefoon krijgt volledige beheerderstoegang. Gebruik liever poort 8971 (https://IP:8971).",
	},
	"warn.noPublic": {
		langEN: "Public address unknown (no Internet access?). Set PUBLIC_HOST to your public IP or a dynamic DNS name.",
		langFR: "Adresse publique inconnue (pas d'accès Internet ?). Renseignez PUBLIC_HOST avec votre IP publique ou un nom DynDNS.",
		langDE: "Öffentliche Adresse unbekannt (kein Internetzugang?). Tragen Sie in PUBLIC_HOST Ihre öffentliche IP oder einen DynDNS-Namen ein.",
		langES: "Dirección pública desconocida (¿sin acceso a Internet?). Indique en PUBLIC_HOST su IP pública o un nombre de DNS dinámico.",
		langIT: "Indirizzo pubblico sconosciuto (nessun accesso a Internet?). Inserisca in PUBLIC_HOST il Suo IP pubblico o un nome DNS dinamico.",
		langNL: "Openbaar adres onbekend (geen internettoegang?). Vul in PUBLIC_HOST uw openbare IP-adres of een DynDNS-naam in.",
	},
	"warn.staleEndpoint": {
		langEN: "Your public address has changed (%s, now %s): the phones set up with the old one can't connect any more (%s). Set PUBLIC_HOST to a dynamic DNS name, then use “New QR” for each of them.",
		langFR: "Votre adresse publique a changé (%s, maintenant %s) : les téléphones configurés avec l'ancienne ne peuvent plus se connecter (%s). Renseignez PUBLIC_HOST avec un nom DynDNS, puis utilisez « Nouveau QR » pour chacun d'eux.",
		langDE: "Ihre öffentliche Adresse hat sich geändert (%s, jetzt %s): Die mit der alten Adresse eingerichteten Telefone können sich nicht mehr verbinden (%s). Tragen Sie in PUBLIC_HOST einen DynDNS-Namen ein und verwenden Sie dann für jedes von ihnen „Neuer QR“.",
		langES: "Su dirección pública ha cambiado (%s, ahora %s): los teléfonos configurados con la antigua ya no pueden conectarse (%s). Indique en PUBLIC_HOST un nombre de DNS dinámico y luego use «Nuevo QR» para cada uno de ellos.",
		langIT: "Il Suo indirizzo pubblico è cambiato (%s, ora %s): i telefoni configurati con quello vecchio non possono più connettersi (%s). Inserisca in PUBLIC_HOST un nome DNS dinamico, poi usi «Nuovo QR» per ciascuno di essi.",
		langNL: "Uw openbare adres is gewijzigd (%s, nu %s): de telefoons die met het oude adres zijn ingesteld, kunnen geen verbinding meer maken (%s). Vul in PUBLIC_HOST een DynDNS-naam in en gebruik daarna voor elk ervan “Nieuwe QR”.",
	},
	"warn.staleEndpointHost": {
		langEN: "Your public address has changed (%s, now %s): the phones set up with the old one can't connect any more (%s). Use “New QR” for each of them.",
		langFR: "Votre adresse publique a changé (%s, maintenant %s) : les téléphones configurés avec l'ancienne ne peuvent plus se connecter (%s). Utilisez « Nouveau QR » pour chacun d'eux.",
		langDE: "Ihre öffentliche Adresse hat sich geändert (%s, jetzt %s): Die mit der alten Adresse eingerichteten Telefone können sich nicht mehr verbinden (%s). Verwenden Sie für jedes von ihnen „Neuer QR“.",
		langES: "Su dirección pública ha cambiado (%s, ahora %s): los teléfonos configurados con la antigua ya no pueden conectarse (%s). Use «Nuevo QR» para cada uno de ellos.",
		langIT: "Il Suo indirizzo pubblico è cambiato (%s, ora %s): i telefoni configurati con quello vecchio non possono più connettersi (%s). Usi «Nuovo QR» per ciascuno di essi.",
		langNL: "Uw openbare adres is gewijzigd (%s, nu %s): de telefoons die met het oude adres zijn ingesteld, kunnen geen verbinding meer maken (%s). Gebruik voor elk ervan “Nieuwe QR”.",
	},
	"warn.manual": {
		langEN: "On your router, forward UDP port %d to %s, port %d.",
		langFR: "Sur votre box, redirigez le port UDP %d vers %s, port %d.",
		langDE: "Leiten Sie auf Ihrem Router den UDP-Port %d an %s, Port %d weiter.",
		langES: "En su router, redirija el puerto UDP %d hacia %s, puerto %d.",
		langIT: "Sul Suo router, inoltri la porta UDP %d verso %s, porta %d.",
		langNL: "Stuur op uw router UDP-poort %d door naar %s, poort %d.",
	},
	"warn.upnpOff": {langEN: "UPnP disabled. %s", langFR: "UPnP désactivé. %s", langDE: "UPnP deaktiviert. %s", langES: "UPnP desactivado. %s", langIT: "UPnP disattivato. %s", langNL: "UPnP uitgeschakeld. %s"},
	"warn.upnpNoRouter": {
		langEN: "No UPnP router answered (UPnP disabled on the router?). %s",
		langFR: "Aucune box UPnP n'a répondu (UPnP désactivé sur la box ?). %s",
		langDE: "Kein UPnP-Router hat geantwortet (UPnP auf dem Router deaktiviert?). %s",
		langES: "Ningún router UPnP ha respondido (¿UPnP desactivado en el router?). %s",
		langIT: "Nessun router UPnP ha risposto (UPnP disattivato sul router?). %s",
		langNL: "Geen enkele UPnP-router heeft geantwoord (UPnP uitgeschakeld op de router?). %s",
	},
	"warn.upnpConflict": {
		langEN: "UDP port %d is already used on the router by another device. %s",
		langFR: "Le port UDP %d est déjà utilisé sur la box par un autre appareil. %s",
		langDE: "Der UDP-Port %d wird auf dem Router bereits von einem anderen Gerät verwendet. %s",
		langES: "El puerto UDP %d ya lo usa otro dispositivo en el router. %s",
		langIT: "La porta UDP %d è già usata sul router da un altro dispositivo. %s",
		langNL: "UDP-poort %d wordt op de router al door een ander apparaat gebruikt. %s",
	},
	"warn.upnpFailed": {
		langEN: "Couldn't open the port automatically (%s). %s",
		langFR: "Ouverture automatique du port impossible (%s). %s",
		langDE: "Der Port konnte nicht automatisch geöffnet werden (%s). %s",
		langES: "No se ha podido abrir el puerto automáticamente (%s). %s",
		langIT: "Impossibile aprire automaticamente la porta (%s). %s",
		langNL: "De poort kon niet automatisch worden geopend (%s). %s",
	},
	"warn.doubleNAT": {
		langEN: "Your router's Internet-side address is %s: it sits behind another router (double NAT). On the upstream router, forward UDP port %d to your router.",
		langFR: "Votre box a l'adresse %s côté Internet : elle est derrière un autre routeur (double NAT). Sur le routeur de tête, redirigez le port UDP %d vers la box.",
		langDE: "Ihr Router hat zum Internet hin die Adresse %s: Er steht hinter einem anderen Router (doppeltes NAT). Leiten Sie am vorgeschalteten Router den UDP-Port %d an Ihren Router weiter.",
		langES: "Su router tiene la dirección %s hacia Internet: está detrás de otro router (doble NAT). En el router principal, redirija el puerto UDP %d hacia su router.",
		langIT: "Il Suo router ha l'indirizzo %s verso Internet: si trova dietro un altro router (doppio NAT). Sul router principale, inoltri la porta UDP %d verso il Suo router.",
		langNL: "Uw router heeft aan de internetkant het adres %s: hij staat achter een andere router (dubbele NAT). Stuur op de bovenliggende router UDP-poort %d door naar uw router.",
	},
	"warn.cgnat": {
		langEN: "The Internet sees address %s but the router reports %s: your ISP may be sharing the IPv4 address (CGNAT). Ask your ISP for a full (static) IPv4.",
		langFR: "Internet voit l'adresse %s mais la box annonce %s : votre opérateur partage peut-être l'adresse IPv4. Demandez-lui une IPv4 complète (fixe).",
		langDE: "Das Internet sieht die Adresse %s, aber der Router meldet %s: Ihr Anbieter teilt möglicherweise die IPv4-Adresse (CGNAT). Fragen Sie ihn nach einer vollwertigen (festen) IPv4.",
		langES: "Internet ve la dirección %s, pero el router anuncia %s: puede que su operador comparta la dirección IPv4 (CGNAT). Pídale una IPv4 completa (fija).",
		langIT: "Internet vede l'indirizzo %s, ma il router riporta %s: forse il Suo operatore condivide l'indirizzo IPv4 (CGNAT). Gli chieda un IPv4 completo (fisso).",
		langNL: "Internet ziet het adres %s, maar de router meldt %s: uw provider deelt misschien het IPv4-adres (CGNAT). Vraag uw provider om een volledig (vast) IPv4-adres.",
	},
	"warn.dyndns": {
		langEN: "If your public address changes from time to time, put a dynamic DNS name in PUBLIC_HOST, otherwise you'll have to rescan the QR code after each change.",
		langFR: "Si votre adresse publique change de temps en temps, mettez un nom DynDNS dans PUBLIC_HOST, sinon il faudra rescanner le QR à chaque changement.",
		langDE: "Wenn sich Ihre öffentliche Adresse ab und zu ändert, tragen Sie einen DynDNS-Namen in PUBLIC_HOST ein, sonst müssen Sie den QR-Code nach jeder Änderung neu scannen.",
		langES: "Si su dirección pública cambia de vez en cuando, ponga un nombre de DNS dinámico en PUBLIC_HOST; si no, tendrá que volver a escanear el QR tras cada cambio.",
		langIT: "Se il Suo indirizzo pubblico cambia di tanto in tanto, inserisca un nome DNS dinamico in PUBLIC_HOST, altrimenti dovrà scansionare di nuovo il codice QR a ogni cambiamento.",
		langNL: "Als uw openbare adres af en toe verandert, vul dan een DynDNS-naam in bij PUBLIC_HOST, anders moet u de QR-code na elke wijziging opnieuw scannen.",
	},

	"html.lang": {langEN: "en", langFR: "fr", langDE: "de", langES: "es", langIT: "it", langNL: "nl"},
	"setup.intro": {
		langEN: "Choose the password for this admin page. It protects adding phones.",
		langFR: "Choisissez le mot de passe de cette page d'administration. Il protège l'ajout de téléphones.",
		langDE: "Wählen Sie das Passwort für diese Administrationsseite. Es schützt das Hinzufügen von Telefonen.",
		langES: "Elija la contraseña de esta página de administración. Protege la adición de teléfonos.",
		langIT: "Scelga la password di questa pagina di amministrazione. Protegge l'aggiunta di telefoni.",
		langNL: "Kies het wachtwoord voor deze beheerpagina. Het beschermt het toevoegen van telefoons.",
	},
	"setup.password": {
		langEN: "Password (8 characters minimum)",
		langFR: "Mot de passe (8 caractères minimum)",
		langDE: "Passwort (mindestens 8 Zeichen)",
		langES: "Contraseña (mínimo 8 caracteres)",
		langIT: "Password (almeno 8 caratteri)",
		langNL: "Wachtwoord (minstens 8 tekens)",
	},
	"setup.confirm":  {langEN: "Confirm", langFR: "Confirmation", langDE: "Bestätigung", langES: "Confirmación", langIT: "Conferma", langNL: "Bevestiging"},
	"setup.save":     {langEN: "Save", langFR: "Enregistrer", langDE: "Speichern", langES: "Guardar", langIT: "Salva", langNL: "Opslaan"},
	"login.password": {langEN: "Password", langFR: "Mot de passe", langDE: "Passwort", langES: "Contraseña", langIT: "Password", langNL: "Wachtwoord"},
	"login.submit":   {langEN: "Sign in", langFR: "Se connecter", langDE: "Anmelden", langES: "Iniciar sesión", langIT: "Accedi", langNL: "Inloggen"},
	"logout":         {langEN: "Sign out", langFR: "Déconnexion", langDE: "Abmelden", langES: "Cerrar sesión", langIT: "Esci", langNL: "Uitloggen"},
	"new.title": {
		langEN: "Add “%s” in PocketNVR",
		langFR: "Ajouter « %s » dans PocketNVR",
		langDE: "„%s“ in PocketNVR hinzufügen",
		langES: "Añadir «%s» en PocketNVR",
		langIT: "Aggiungere «%s» in PocketNVR",
		langNL: "“%s” toevoegen in PocketNVR",
	},
	"new.qrAlt": {
		langEN: "Configuration QR code",
		langFR: "QR code de configuration",
		langDE: "QR-Code der Konfiguration",
		langES: "Código QR de configuración",
		langIT: "Codice QR della configurazione",
		langNL: "QR-code van de configuratie",
	},
	"new.howTo": {
		langEN: "In the PocketNVR app: <b>VPN access → Scan QR</b>.",
		langFR: "Dans l'appli PocketNVR : <b>Accès VPN → Scanner le QR</b>.",
		langDE: "In der App PocketNVR: <b>VPN-Zugang → QR scannen</b>.",
		langES: "En la app PocketNVR: <b>Acceso VPN → Escanear QR</b>.",
		langIT: "Nell'app PocketNVR: <b>Accesso VPN → Scansiona QR</b>.",
		langNL: "In de app PocketNVR: <b>VPN-toegang → QR scannen</b>.",
	},
	"new.open": {langEN: "Open in PocketNVR", langFR: "Ouvrir dans PocketNVR", langDE: "In PocketNVR öffnen", langES: "Abrir en PocketNVR", langIT: "Apri in PocketNVR", langNL: "Openen in PocketNVR"},
	"new.openHint": {
		langEN: "If you're reading this page on the iPhone itself.",
		langFR: "Si vous lisez cette page sur l'iPhone lui-même.",
		langDE: "Wenn Sie diese Seite auf dem iPhone selbst lesen.",
		langES: "Si está leyendo esta página en el propio iPhone.",
		langIT: "Se sta leggendo questa pagina sull'iPhone stesso.",
		langNL: "Als u deze pagina op de iPhone zelf leest.",
	},
	"new.download": {
		langEN: "Download the .conf file",
		langFR: "Télécharger le fichier .conf",
		langDE: "Die .conf-Datei herunterladen",
		langES: "Descargar el archivo .conf",
		langIT: "Scarica il file .conf",
		langNL: "Het .conf-bestand downloaden",
	},
	"new.expiry": {
		langEN: "This QR code holds the phone's private key. It isn't stored: it disappears in 15 minutes. After that, use “New QR”.",
		langFR: "Ce QR contient la clé privée du téléphone. Il n'est pas conservé : il disparaît dans 15 minutes. Ensuite, utilisez « Nouveau QR ».",
		langDE: "Dieser QR-Code enthält den privaten Schlüssel des Telefons. Er wird nicht gespeichert: Er verschwindet in 15 Minuten. Danach verwenden Sie „Neuer QR“.",
		langES: "Este QR contiene la clave privada del teléfono. No se conserva: desaparece en 15 minutos. Después, use «Nuevo QR».",
		langIT: "Questo QR contiene la chiave privata del telefono. Non viene conservato: scompare tra 15 minuti. Dopo, usi «Nuovo QR».",
		langNL: "Deze QR bevat de privésleutel van de telefoon. Hij wordt niet bewaard: hij verdwijnt over 15 minuten. Gebruik daarna “Nieuwe QR”.",
	},
	"status.title":      {langEN: "Status", langFR: "État", langDE: "Status", langES: "Estado", langIT: "Stato", langNL: "Status"},
	"status.reachable":  {langEN: "reachable", langFR: "joignable", langDE: "erreichbar", langES: "accesible", langIT: "raggiungibile", langNL: "bereikbaar"},
	"status.down":       {langEN: "unreachable", langFR: "injoignable", langDE: "nicht erreichbar", langES: "inaccesible", langIT: "non raggiungibile", langNL: "niet bereikbaar"},
	"status.phoneURL":   {langEN: "Address for phones", langFR: "Adresse pour les téléphones", langDE: "Adresse für die Telefone", langES: "Dirección para los teléfonos", langIT: "Indirizzo per i telefoni", langNL: "Adres voor de telefoons"},
	"status.public":     {langEN: "Public address", langFR: "Adresse publique", langDE: "Öffentliche Adresse", langES: "Dirección pública", langIT: "Indirizzo pubblico", langNL: "Openbaar adres"},
	"status.unknown":    {langEN: "unknown", langFR: "inconnue", langDE: "unbekannt", langES: "desconocida", langIT: "sconosciuto", langNL: "onbekend"},
	"status.udpPort":    {langEN: "UDP port", langFR: "Port UDP", langDE: "UDP-Port", langES: "Puerto UDP", langIT: "Porta UDP", langNL: "UDP-poort"},
	"status.router":     {langEN: "router", langFR: "box", langDE: "Router", langES: "router", langIT: "router", langNL: "router"},
	"status.upnpOpen":   {langEN: "open", langFR: "ouvert", langDE: "offen", langES: "abierto", langIT: "aperta", langNL: "open"},
	"status.upnpOn":     {langEN: "on %s", langFR: "sur %s", langDE: "auf %s", langES: "en %s", langIT: "su %s", langNL: "op %s"},
	"status.upnpFailed": {langEN: "failed", langFR: "échec", langDE: "fehlgeschlagen", langES: "error", langIT: "errore", langNL: "mislukt"},
	"status.upnpOff":    {langEN: "UPnP disabled", langFR: "UPnP désactivé", langDE: "UPnP deaktiviert", langES: "UPnP desactivado", langIT: "UPnP disattivato", langNL: "UPnP uitgeschakeld"},
	"phones.title":      {langEN: "Phones", langFR: "Téléphones", langDE: "Telefone", langES: "Teléfonos", langIT: "Telefoni", langNL: "Telefoons"},
	"phones.lastSeen":   {langEN: "Last connection:", langFR: "Dernière connexion :", langDE: "Letzte Verbindung:", langES: "Última conexión:", langIT: "Ultima connessione:", langNL: "Laatste verbinding:"},
	"phones.newQR":      {langEN: "New QR", langFR: "Nouveau QR", langDE: "Neuer QR", langES: "Nuevo QR", langIT: "Nuovo QR", langNL: "Nieuwe QR"},
	"phones.delete":     {langEN: "Delete", langFR: "Supprimer", langDE: "Löschen", langES: "Eliminar", langIT: "Elimina", langNL: "Verwijderen"},
	"phones.confirm": {
		langEN: "Delete %s? This phone will lose access.",
		langFR: "Supprimer %s ? Ce téléphone n'aura plus accès.",
		langDE: "%s löschen? Dieses Telefon verliert den Zugriff.",
		langES: "¿Eliminar %s? Este teléfono perderá el acceso.",
		langIT: "Eliminare %s? Questo telefono perderà l'accesso.",
		langNL: "%s verwijderen? Deze telefoon verliest de toegang.",
	},
	"phones.none": {langEN: "No phones yet.", langFR: "Aucun téléphone pour l'instant.", langDE: "Noch keine Telefone.", langES: "Todavía no hay teléfonos.", langIT: "Ancora nessun telefono.", langNL: "Nog geen telefoons."},
	"phones.name": {
		langEN: "Phone name (e.g. Alex's iPhone)",
		langFR: "Nom du téléphone (ex. iPhone d'Alex)",
		langDE: "Name des Telefons (z. B. iPhone von Alex)",
		langES: "Nombre del teléfono (p. ej., iPhone de Alex)",
		langIT: "Nome del telefono (es. iPhone di Alex)",
		langNL: "Naam van de telefoon (bijv. iPhone van Alex)",
	},
	"phones.add": {langEN: "Add a phone", langFR: "Ajouter un téléphone", langDE: "Telefon hinzufügen", langES: "Añadir un teléfono", langIT: "Aggiungi un telefono", langNL: "Telefoon toevoegen"},
	"footer": {
		langEN: "The Bridge only gives access to Frigate: the rest of your network can't be reached by the phones.",
		langFR: "Le Bridge ne donne accès qu'à Frigate : le reste de votre réseau n'est pas joignable par les téléphones.",
		langDE: "Die Bridge gibt nur Zugriff auf Frigate: Der Rest Ihres Netzwerks ist für die Telefone nicht erreichbar.",
		langES: "El Bridge solo da acceso a Frigate: el resto de su red no es accesible para los teléfonos.",
		langIT: "Il Bridge dà accesso solo a Frigate: il resto della Sua rete non è raggiungibile dai telefoni.",
		langNL: "De Bridge geeft alleen toegang tot Frigate: de rest van uw netwerk is niet bereikbaar voor de telefoons.",
	},

	"ago.never":   {langEN: "never", langFR: "jamais", langDE: "nie", langES: "nunca", langIT: "mai", langNL: "nooit"},
	"ago.now":     {langEN: "just now", langFR: "à l'instant", langDE: "gerade eben", langES: "ahora mismo", langIT: "proprio ora", langNL: "zojuist"},
	"ago.seconds": {langEN: "%d s ago", langFR: "il y a %d s", langDE: "vor %d s", langES: "hace %d s", langIT: "%d s fa", langNL: "%d s geleden"},
	"ago.minutes": {langEN: "%d min ago", langFR: "il y a %d min", langDE: "vor %d Min.", langES: "hace %d min", langIT: "%d min fa", langNL: "%d min geleden"},
	"ago.hours":   {langEN: "%d h ago", langFR: "il y a %d h", langDE: "vor %d Std.", langES: "hace %d h", langIT: "%d h fa", langNL: "%d u geleden"},
	"ago.date":    {langEN: "2006-01-02", langFR: "02/01/2006", langDE: "02.01.2006", langES: "02/01/2006", langIT: "02/01/2006", langNL: "02-01-2006"},
	"unit.b":      {langEN: "B", langFR: "o", langDE: "B", langES: "B", langIT: "B", langNL: "B"},
	"unit.kb":     {langEN: "KB", langFR: "Ko", langDE: "KB", langES: "KB", langIT: "KB", langNL: "KB"},
	"unit.mb":     {langEN: "MB", langFR: "Mo", langDE: "MB", langES: "MB", langIT: "MB", langNL: "MB"},
	"unit.gb":     {langEN: "GB", langFR: "Go", langDE: "GB", langES: "GB", langIT: "GB", langNL: "GB"},
}
